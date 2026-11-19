// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `governance::runtime` off-path code (see `crate::off_path::governance`).

use crate::governance::recovery::{
    RecoveryError, RecoveryEvent, RecoveryItem, RecoverySelection, RecoveryState,
};
use busbar_contract::json::{self, JsonValueMutTrait as _, JsonValueTrait as _};

/// `recovery`: summarize a replayed recovery Store into one verified selection per operation
/// (boot attach and recovery checks).
pub(crate) fn recovery_summarize_chains(
    events: Vec<RecoveryEvent>,
) -> Result<Vec<RecoverySelection>, RecoveryError> {
    let mut selections = std::collections::BTreeMap::<[u8; 16], RecoverySelection>::new();
    for event in events {
        if let Some(selection) = selections.get_mut(&event.operation_id) {
            event.follows(Some(&selection.selected))?;
            selection.selected = event;
        } else {
            event.follows(None)?;
            selections.insert(
                event.operation_id,
                RecoverySelection {
                    initial: event.clone(),
                    selected: event,
                },
            );
        }
    }
    Ok(selections.into_values().collect())
}

/// `recovery`: the operator's recovery list page: unsettled local selections, overlaid by
/// unsettled foreign inspections, from `after`, at most `limit` (admin control plane).
pub(crate) fn recovery_list_page(
    local: Vec<RecoveryEvent>,
    foreign: Vec<crate::governance::recovery::RecoveryInspection>,
    after: Option<[u8; 16]>,
    limit: usize,
) -> Vec<RecoveryItem> {
    let mut items: std::collections::BTreeMap<_, _> = local
        .into_iter()
        .filter(|event| event.state != RecoveryState::Settled)
        .map(|event| (event.operation_id, RecoveryItem::from_event(&event)))
        .collect();
    for inspection in foreign {
        if inspection.event.state == RecoveryState::Settled {
            continue;
        }
        let mut item = RecoveryItem::from_event(&inspection.event);
        item.owner_node = Some(inspection.owner_node);
        item.can_resolve = false;
        items.insert(item.operation_id, item);
    }
    items
        .into_iter()
        .filter(|(id, _)| after.is_none_or(|after| *id > after))
        .take(limit)
        .map(|(_, item)| item)
        .collect()
}

/// `recovery`: whether any operation still holds custody work (shutdown check).
pub(crate) fn recovery_any_unsettled<'a>(
    mut entries: impl Iterator<Item = &'a crate::governance::recovery::RecoveryEntry>,
) -> bool {
    entries.any(crate::governance::recovery::RecoveryEntry::unsettled)
}

/// `recovery`: `(staged, selected)` custody counts at a non-retired exit (SHUTDOWN-HANG §5).
pub(crate) fn recovery_custody_counts<'a>(
    entries: impl Iterator<Item = &'a crate::governance::recovery::RecoveryEntry>,
) -> (usize, usize) {
    entries.fold((0, 0), |(staged, selected), entry| {
        let (s, x) = entry.custody();
        (staged + usize::from(s), selected + usize::from(x))
    })
}

/// `recovery`: every selected recovery event (boot attach, recovery resume, operator list).
pub(crate) fn recovery_selected_events<'a>(
    entries: impl Iterator<Item = &'a crate::governance::recovery::RecoveryEntry>,
) -> Vec<RecoveryEvent> {
    entries.filter_map(|entry| entry.selected.clone()).collect()
}

/// `raw_recovery`: a recovery custody payload, encoded once per durable custody event.
pub(crate) fn raw_recovery_encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, json::Error> {
    json::to_vec(value)
}

/// `raw_recovery`: a recovered operation's original cells, plain before dated, rebuilt once per
/// recovered operation.
pub(crate) fn raw_recovery_cells<T>(plain: Option<T>, dated: Option<T>) -> Vec<T> {
    plain.into_iter().chain(dated).collect()
}

/// `raw_recovery`: the bucket a usage recovery child names, owned once per flushed child.
pub(crate) fn raw_recovery_bucket(bucket: &str) -> String {
    bucket.to_owned()
}

/// `raw_recovery`: each selected operation's identity and revision, compared before and after
/// one recovery resume pass.
pub(crate) fn raw_recovery_revisions(events: &[RecoveryEvent]) -> Vec<([u8; 16], u64)> {
    events
        .iter()
        .map(|event| (event.operation_id, event.revision))
        .collect()
}

/// `raw_recovery`: the borrowed cells a recovered operation resubmits once.
pub(crate) fn raw_recovery_cell_refs(
    owned: &[(String, u64, busbar_contract::records::UsageDelta)],
) -> Vec<(&str, u64, busbar_contract::records::UsageDelta)> {
    owned
        .iter()
        .map(|(bucket, window, delta)| (bucket.as_str(), *window, delta.clone()))
        .collect()
}

/// `raw_recovery`: the selected operations' identities, indexed once per custody capture.
pub(crate) fn raw_recovery_operation_ids(
    events: &[RecoveryEvent],
) -> std::collections::BTreeSet<[u8; 16]> {
    events.iter().map(|event| event.operation_id).collect()
}

/// `raw_recovery`: a recovery walk's work queue, seeded with its root.
pub(crate) fn raw_recovery_queue<T>(root: T) -> std::collections::VecDeque<T> {
    std::collections::VecDeque::from([root])
}

/// `raw_recovery`: whether a recovered child's payload equals its retained descriptor, both with
/// `origin` removed (recovery selection).
pub(crate) fn raw_recovery_same_child<E>(
    actual: &[u8],
    expected: &[u8],
    invalid: impl Fn(&dyn std::fmt::Display) -> E,
) -> Result<bool, E> {
    let mut actual: json::Value = json::parse_value(actual).map_err(|e| invalid(&e))?;
    actual
        .as_object_mut()
        .ok_or_else(|| invalid(&"child payload is not an object"))?
        .remove(&"origin");
    let mut expected: json::Value = json::parse_value(expected).map_err(|e| invalid(&e))?;
    expected
        .as_object_mut()
        .ok_or_else(|| invalid(&"child template is not an object"))?
        .remove(&"origin");
    Ok(actual == expected)
}

/// `raw_recovery`: a child Intent's raw body checked field for field against its parent's
/// template, which must carry no origin of its own (recovery origin proof).
pub(crate) fn raw_recovery_child_matches_template(
    child: &[u8],
    template: &[u8],
) -> Result<(), RecoveryError> {
    let invalid = |reason: &str| RecoveryError::Invalid(reason.to_owned());
    let mut actual: json::Value = json::parse_value(child).map_err(|error| {
        crate::governance::rendered_error(
            RecoveryError::Invalid,
            format_args!("invalid child payload: {error}"),
        )
    })?;
    actual
        .as_object_mut()
        .ok_or_else(|| invalid("child payload is not an object"))?
        .remove(&"origin");
    let mut expected: json::Value = json::parse_value(template).map_err(|error| {
        crate::governance::rendered_error(
            RecoveryError::Invalid,
            format_args!("invalid child template: {error}"),
        )
    })?;
    let expected_object = expected
        .as_object_mut()
        .ok_or_else(|| invalid("child template is not an object"))?;
    if expected_object
        .get(&"origin")
        .is_some_and(|origin| !origin.is_null())
    {
        return Err(invalid("child template already contains an origin"));
    }
    expected_object.remove(&"origin");
    if actual != expected {
        return Err(invalid("child raw body differs from exact parent template"));
    }
    Ok(())
}

/// `raw_recovery`: an operator's verdict on a migrated foreign operation rewrites its handoffs
/// once: every child the stored custody did not already hold gets its migrated identity. The
/// payload is rewritten as a tree so every other field keeps its exact stored form.
pub(crate) fn raw_recovery_identify_handoffs(
    payload: &[u8],
    preserved: &[crate::governance::recovery::RecoveryChild],
    mut identify: impl FnMut(
        &mut crate::governance::recovery::RecoveryChild,
        usize,
    ) -> Result<(), RecoveryError>,
) -> Result<Vec<u8>, RecoveryError> {
    let invalid = |error: &dyn std::fmt::Display| {
        crate::governance::rendered_error(RecoveryError::Invalid, error)
    };
    let mut value: json::Value = json::parse_value(payload).map_err(|e| invalid(&e))?;
    let mut handoffs: Vec<crate::governance::recovery::RecoveryChild> = json::from_value(
        &value
            .get("handoffs")
            .cloned()
            .unwrap_or_else(|| json::json!([])),
    )
    .map_err(|e| invalid(&e))?;
    for (index, child) in handoffs.iter_mut().enumerate() {
        if !preserved
            .iter()
            .any(|held| held.operation_id == child.operation_id)
        {
            identify(child, index)?;
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    if handoffs
        .iter()
        .any(|child| !seen.insert(child.operation_id))
    {
        return Err(RecoveryError::Invalid(
            "migrated handoff identity collision".into(),
        ));
    }
    let object = value
        .as_object_mut()
        .ok_or_else(|| RecoveryError::Invalid("raw custody is not an object".into()))?;
    let handoffs = json::to_value(&handoffs).map_err(|e| invalid(&e))?;
    object.insert("handoffs", handoffs);
    json::to_vec(&value).map_err(|e| invalid(&e))
}

/// `raw_recovery`: a child template stamped with its origin, once, when recovery selects it.
/// The template is extended as a tree so every field keeps its exact stored form.
pub(crate) fn raw_recovery_stamp_origin<E>(
    template: &[u8],
    origin: &crate::governance::recovery::RecoveryOrigin,
    invalid: impl Fn(&dyn std::fmt::Display) -> E,
) -> Result<Vec<u8>, E> {
    let mut payload: json::Value = json::parse_value(template).map_err(|e| invalid(&e))?;
    let object = payload
        .as_object_mut()
        .ok_or_else(|| invalid(&"child template is not an object"))?;
    if object
        .get(&"origin")
        .is_some_and(|origin| !origin.is_null())
    {
        return Err(invalid(&"child template already has an origin"));
    }
    let origin = json::to_value(origin).map_err(|e| invalid(&e))?;
    object.insert("origin", origin);
    json::to_vec(&payload).map_err(|e| invalid(&e))
}

use crate::governance::exact_debt::{BudgetFlushFlight, ExactModelDelta, ExactUsageDelta};
use busbar_contract::count::{Count, CountError, COUNT_SCALE};
use busbar_contract::records::UsageDelta;

/// `exact_debt`: whether every model row of a flush debt is zero (flusher and window roll).
pub(crate) fn exact_debt_models_zero(models: &[ExactModelDelta]) -> bool {
    models
        .iter()
        .all(|model| model.usage_units.values().all(|count| *count == 0))
}

/// `exact_debt`: the row of a flush debt that names this model (flusher and window roll).
pub(crate) fn exact_debt_model_index(models: &[ExactModelDelta], model: &str) -> Option<usize> {
    models.iter().position(|row| row.model == model)
}

/// `exact_debt`: the row of a flush debt named `era SEP model`, found by comparing the three
/// parts where they lie: the dated name is not built to look a row up.
pub(crate) fn exact_debt_era_model_index(
    models: &[ExactModelDelta],
    era: &str,
    separator: char,
    model: &str,
) -> Option<usize> {
    models.iter().position(|row| {
        row.model
            .strip_prefix(era)
            .and_then(|rest| rest.strip_prefix(separator))
            == Some(model)
    })
}

/// `exact_debt`: an acknowledged or parked signed delta as exact flush debt.
pub(crate) fn exact_debt_from_signed(delta: &UsageDelta) -> Result<ExactUsageDelta, CountError> {
    Ok(ExactUsageDelta {
        requests: i128::from(delta.requests),
        billable_requests: i128::from(delta.billable_requests),
        models: delta
            .models
            .iter()
            .map(|model| {
                Ok(ExactModelDelta {
                    model: model.model.clone(),
                    scale: COUNT_SCALE,
                    usage_units: model
                        .usage_units
                        .iter()
                        .map(|(unit, count)| {
                            Count::from_stored(*count, model.scale)
                                .map(|n| (unit.clone(), n.micros()))
                        })
                        .collect::<Result<_, _>>()?,
                })
            })
            .collect::<Result<_, CountError>>()?,
    })
}

/// `exact_debt`: a signed delta handed over as exact flush debt (a refund parked in a rolled
/// window). The same checks in the same order and the same error as `exact_debt_from_signed`;
/// each model and unit name moves into the debt, none is copied.
pub(crate) fn exact_debt_from_signed_owned(
    delta: UsageDelta,
) -> Result<ExactUsageDelta, CountError> {
    Ok(ExactUsageDelta {
        requests: i128::from(delta.requests),
        billable_requests: i128::from(delta.billable_requests),
        models: delta
            .models
            .into_iter()
            .map(|model| {
                let scale = model.scale;
                Ok(ExactModelDelta {
                    model: model.model,
                    scale: COUNT_SCALE,
                    usage_units: model
                        .usage_units
                        .into_iter()
                        .map(|(unit, count)| {
                            Count::from_stored(count, scale).map(|n| (unit, n.micros()))
                        })
                        .collect::<Result<_, _>>()?,
                })
            })
            .collect::<Result<_, CountError>>()?,
    })
}

/// `exact_debt`: exact flush debt as the signed wire delta a flush chunk sends, when it fits.
/// The debt is handed over: each model and unit name moves into the chunk's own rows.
pub(crate) fn exact_debt_signed(debt: ExactUsageDelta) -> Option<UsageDelta> {
    Some(UsageDelta {
        requests: i64::try_from(debt.requests).ok()?,
        billable_requests: i64::try_from(debt.billable_requests).ok()?,
        models: debt
            .models
            .into_iter()
            .map(|model| {
                let scale = model.scale;
                Some(busbar_contract::records::ModelTokensDelta {
                    model: model.model,
                    scale: COUNT_SCALE,
                    usage_units: model
                        .usage_units
                        .into_iter()
                        .filter(|(_, count)| *count != 0)
                        .map(|(unit, count)| {
                            Count::from_stored(count, scale)
                                .ok()
                                .map(|count| (unit, count.micros()))
                        })
                        .collect::<Option<_>>()?,
                })
            })
            .collect::<Option<_>>()?,
    })
}

/// `exact_debt`: the dated model name of an era segment, rebuilt when flush debt is segmented.
pub(crate) fn exact_debt_era_model(era: &str, separator: char, model: &str) -> String {
    format!("{era}{separator}{model}")
}

/// `exact_debt`: keep only the positive segments of a custody's raw usage, in place (custody
/// capture): the map the caller owns is narrowed; nothing is copied.
pub(crate) fn exact_debt_keep_positive<K: Ord>(segments: &mut std::collections::BTreeMap<K, i128>) {
    segments.retain(|_, count| *count > 0);
}

/// `exact_debt`: whether every segment of a custody's raw usage is zero (custody capture).
pub(crate) fn exact_debt_all_zero<K>(segments: &std::collections::BTreeMap<K, i128>) -> bool {
    segments.values().all(|count| *count == 0)
}

/// `exact_debt`: the windows a cell has debt in, ascending: its current window and every parked
/// one (the flusher, once per cell).
pub(crate) fn exact_debt_flush_windows(
    current: u64,
    rolled: impl Iterator<Item = u64>,
    rolled_eras: impl Iterator<Item = u64>,
) -> std::collections::BTreeSet<u64> {
    let mut windows = std::collections::BTreeSet::from([current]);
    windows.extend(rolled);
    windows.extend(rolled_eras);
    windows
}

/// `exact_debt`: drop a window's parked debt once its flight captured it (the flusher).
pub(crate) fn exact_debt_unpark<T>(parked: &mut Vec<(u64, T)>, window: u64) {
    parked.retain(|(at, _)| *at != window);
}

/// `exact_debt`: every in-flight flush flight (the flusher's resume pass).
pub(crate) fn exact_debt_flights<'a>(
    flights: impl Iterator<Item = &'a std::sync::Arc<BudgetFlushFlight>>,
) -> Vec<std::sync::Arc<BudgetFlushFlight>> {
    flights.cloned().collect()
}

/// `exact_debt`: a deleted bucket's in-flight flush flights, settled once at key or group
/// deletion.
pub(crate) fn exact_debt_bucket_flights(
    flights: &std::collections::BTreeMap<
        (busbar_contract::kept::Text, u64),
        std::sync::Arc<BudgetFlushFlight>,
    >,
    bucket: &str,
) -> Vec<std::sync::Arc<BudgetFlushFlight>> {
    flights
        .iter()
        .filter(|((id, _), _)| id == bucket)
        .map(|(_, flight)| flight.clone())
        .collect()
}

/// `exact_debt`: drive each flush flight in turn (the flusher's resume pass): the receipts it
/// confirmed and one rendered error per flight that failed.
pub(crate) async fn exact_debt_resume_flights(
    state: &crate::governance::GovState,
    flights: Vec<std::sync::Arc<BudgetFlushFlight>>,
    final_flush: bool,
) -> (usize, Vec<String>) {
    let mut confirmed = 0;
    let mut errors = Vec::new();
    for flight in flights {
        let (done, error) = state.drive_budget_flush_flight(&flight, final_flush).await;
        confirmed += done;
        if let Some(error) = error {
            errors.push(format!("{}@{}: {error}", flight.bucket, flight.window));
        }
    }
    (confirmed, errors)
}

use crate::governance::unit_checkpoint::UnitCheckpoint;
use busbar_contract::records::{RecordStoreError, RecordStoreResult};

/// `unit_checkpoint`: a running-unit checkpoint's shape checked (boot replay, the flusher, the
/// checkpoint Store).
pub(crate) fn unit_checkpoint_validate(snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
    let error = |message: &'static str| RecordStoreError::fixed(message);
    if let Some(partitions) = &snapshot.partitions {
        partitions.validate(snapshot)?;
    }
    if let Some(evidence) = &snapshot.measurement {
        evidence
            .validate(snapshot)
            .map_err(|_| error("invalid host measurement origin"))?;
    }
    if snapshot.principal.is_empty()
        || snapshot
            .units
            .iter()
            .any(|(class, count)| class.is_empty() || count.is_negative())
    {
        return Err(error("invalid running money principal or quantity"));
    }
    let mut targets = std::collections::BTreeSet::new();
    if snapshot
        .targets
        .iter()
        .any(|target| target.bucket.is_empty() || !targets.insert((&target.bucket, target.window)))
    {
        return Err(error("duplicate or empty running money target"));
    }
    if let Some(events) = &snapshot.terminal {
        if !snapshot.ended {
            return Err(error("running checkpoint contains terminal operations"));
        }
        let mut operations = std::collections::BTreeSet::new();
        for event in events {
            event
                .follows(None)
                .map_err(|e| RecordStoreError::from(e.to_string()))?;
            if !operations.insert(event.operation_id) {
                return Err(error("duplicate unit terminal operation"));
            }
        }
    }
    Ok(())
}

/// `unit_checkpoint/book`: the flush pass's ids, every `first` entry before every `then` entry,
/// each group in map order (SHUTDOWN-HANG F3.3: terminal before moved running entries).
pub(crate) fn unit_checkpoint_book_flush_order<'a, T: 'a>(
    entries: impl Iterator<Item = (&'a [u8; 16], &'a T)>,
    first: impl Fn(&T) -> bool,
    then: impl Fn(&T) -> bool,
) -> Vec<[u8; 16]> {
    let mut firsts = Vec::new();
    let mut thens = Vec::new();
    for (id, entry) in entries {
        if first(entry) {
            firsts.push(*id);
        } else if then(entry) {
            thens.push(*id);
        }
    }
    firsts.extend(thens);
    firsts
}

/// `unit_checkpoint/book`: one value per pending checkpoint (a non-retired exit's evidence).
pub(crate) fn unit_checkpoint_book_map<'a, T: 'a, U>(
    entries: impl Iterator<Item = (&'a [u8; 16], &'a T)>,
    f: impl FnMut((&'a [u8; 16], &'a T)) -> U,
) -> Vec<U> {
    entries.map(f).collect()
}

/// `unit_checkpoint/book`: whether every pending checkpoint satisfies `f` (boot only).
pub(crate) fn unit_checkpoint_book_all<'a, T: 'a>(
    mut entries: impl Iterator<Item = &'a T>,
    f: impl FnMut(&'a T) -> bool,
) -> bool {
    entries.all(f)
}

/// `unit_checkpoint_counts`: a terminal unit's usage recovery Intents, one per target that
/// carries debt, staged once per terminal unit (the flusher).
pub(crate) fn unit_checkpoint_counts_events<T>(
    staged: impl Iterator<Item = RecordStoreResult<Option<T>>>,
) -> RecordStoreResult<Vec<T>> {
    let mut events = Vec::new();
    for event in staged {
        if let Some(event) = event? {
            events.push(event);
        }
    }
    Ok(events)
}

/// `unit_checkpoint_counts`: the raw units a terminal unit meters, once per terminal unit.
pub(crate) fn unit_checkpoint_counts_usage_units(
    units: &std::collections::BTreeMap<String, Count>,
    keep: impl Fn(&str, &Count) -> bool,
) -> std::collections::BTreeMap<String, Count> {
    units
        .iter()
        .filter(|(name, count)| keep(name, count))
        .map(|(name, count)| (name.clone(), *count))
        .collect()
}

/// `unit_checkpoint_counts`: the distinct shards a recovered unit's targets live in, ascending
/// (once per recovered-unit reload).
pub(crate) fn unit_checkpoint_counts_shards(indices: impl Iterator<Item = usize>) -> Vec<usize> {
    let mut shards: Vec<usize> = indices.collect();
    shards.sort();
    shards.dedup();
    shards
}

/// `unit_checkpoint_counts`: every captured target, or the first refusal (recovered-unit reload).
pub(crate) fn unit_checkpoint_counts_try_collect<T>(
    items: impl Iterator<Item = RecordStoreResult<T>>,
) -> RecordStoreResult<Vec<T>> {
    items.collect()
}

/// `unit_checkpoint_counts`: whether an ordinary flush flight still holds this bucket
/// (recovered-unit reload).
pub(crate) fn unit_checkpoint_counts_in_flight(
    flights: &std::collections::BTreeMap<
        (busbar_contract::kept::Text, u64),
        std::sync::Arc<BudgetFlushFlight>,
    >,
    bucket: &str,
) -> bool {
    flights.keys().any(|(held, _)| held == bucket)
}

/// `unit_checkpoint_store`: a recovered unit's original audit line, found by one historical
/// journal replay once per terminal unit (A27c §8b bounds it), confirmed against the live head.
pub(crate) async fn unit_checkpoint_store_find_audit(
    journal: &crate::persistence::journal::runtime::RuntimeJournal,
    unit: u64,
    incarnation: u64,
) -> RecordStoreResult<Option<(u64, busbar_kernel_audit::AuditRecord)>> {
    use busbar_kernel_wal::{JournalRecord, RecordClass};
    let error = |e: &dyn std::fmt::Debug| RecordStoreError::from(format!("unit checkpoint: {e:?}"));
    journal.flush().await.map_err(|e| error(&e))?;
    let history = journal.history().map_err(|e| error(&e))?;
    // One walk from the replay base (SEALING-FIX §3.9): a cut during it restarts it, with its
    // duplicate check; the target is above the floor by (b), so a restart still finds it. Kept
    // copies are context, never audit lines.
    use crate::persistence::journal::Error as WalkError;
    type Found = (Option<(u64, busbar_kernel_audit::AuditRecord)>, bool);
    let walked = history
        .walk(
            || (None, false),
            |(found, duplicate): &mut Found, original, kept| {
                if kept || *duplicate {
                    return Ok(());
                }
                let record =
                    JournalRecord::decode(&original.body).map_err(|_| WalkError::Corrupt)?;
                if record.class != RecordClass::Transaction {
                    return Ok(());
                }
                let audit = busbar_kernel_audit::from_journal_body(
                    &record.body,
                    &crate::Registration::meter_class,
                )
                .map_err(|_| WalkError::Corrupt)?;
                if let Some(audit) = audit {
                    if audit.what.unit_key.get() == unit && audit.what.incarnation == incarnation {
                        *duplicate = found.is_some();
                        *found = Some((original.node_seq, audit));
                    }
                }
                Ok(())
            },
        )
        .await;
    let ((found, duplicate), proof) = walked.map_err(|e| error(&e))?;
    if duplicate {
        return Err(RecordStoreError(
            "duplicate original audit for recovered unit".into(),
        ));
    }
    // The scan ran without the driver; confirm its prefix against the live
    // head so a concurrent append is not mistaken for lost authority.
    journal
        .confirm_live_owned(Some(&proof))
        .await
        .map_err(|e| error(&e))?;
    Ok(found)
}

/// `unit_checkpoint_store`: the key prefix of this node's checkpoint slots.
pub(crate) fn unit_checkpoint_store_prefix(family: &[u8], node: u64) -> Vec<u8> {
    let mut key = family.to_vec();
    key.extend_from_slice(&node.to_be_bytes());
    key
}

/// `unit_checkpoint_store`: a checkpoint head or body, encoded once per persisted revision.
pub(crate) fn unit_checkpoint_store_encode<T: serde::Serialize>(
    value: &T,
) -> Result<Vec<u8>, json::Error> {
    json::to_vec(value)
}

/// `unit_checkpoint_store`: the replayed checkpoints in id order (boot, when the sink attaches).
pub(crate) fn unit_checkpoint_store_replayed(
    replayed: std::collections::BTreeMap<[u8; 16], UnitCheckpoint>,
) -> Vec<UnitCheckpoint> {
    replayed.into_values().collect()
}

use crate::governance::{CredentialIndex, CredentialSecret, VirtualKey};

/// `identity_runtime`: drop the cached credentials an identity mutation retired (control plane).
pub(crate) fn identity_runtime_retain_credentials(
    index: &mut CredentialIndex,
    mut keep: impl FnMut(&(std::sync::Arc<VirtualKey>, CredentialSecret)) -> bool,
) {
    index.retain(|_, entry| keep(entry));
}

/// `identity_runtime`: a minted credential's id, once per signed-token mint (control plane).
pub(crate) fn identity_runtime_credential_id(random: &[u8; 16]) -> String {
    format!("cred_{}", hex::encode(random))
}

/// `identity_runtime`: the audit resource of one at-rest rewrap pass.
pub(crate) fn identity_runtime_rewrap_resource(kid: &str, rows: impl std::fmt::Display) -> String {
    format!("kid:{kid} rows:{rows}")
}

/// The identity cache maps: key revisions, credential revisions, live keys by id, credentials.
pub(crate) type IdentityCacheMaps = (
    foldhash::HashMap<String, u64>,
    foldhash::HashMap<String, u64>,
    foldhash::HashMap<String, std::sync::Arc<VirtualKey>>,
    CredentialIndex,
);

/// `identity_runtime`: the identity cache's revision, key and credential maps, rebuilt from a
/// confirmed snapshot (boot and refresh).
pub(crate) fn identity_runtime_cache_maps(
    keys: Vec<VirtualKey>,
    credentials: Vec<CredentialSecret>,
    now: u64,
) -> IdentityCacheMaps {
    let key_revisions = keys
        .iter()
        .map(|key| (key.id.clone(), key.revision))
        .collect();
    let credential_revisions = credentials
        .iter()
        .map(|cred| (cred.meta.id.clone(), cred.meta.revision))
        .collect();
    let by_id: foldhash::HashMap<_, _> = keys
        .into_iter()
        .filter(|key| key.deleted_at.is_none())
        .map(|key| (key.id.clone(), std::sync::Arc::new(key)))
        .collect();
    let by_credential = credentials
        .into_iter()
        .filter(|cred| cred.meta.is_live(now))
        .filter_map(|cred| {
            by_id.get(&cred.meta.key_id).map(|key| {
                (
                    (cred.meta.kind.clone(), cred.meta.public_id.clone()),
                    (key.clone(), cred),
                )
            })
        })
        .collect();
    (key_revisions, credential_revisions, by_id, by_credential)
}

/// `mint_policy`: the runtime mint policy, resolved once at boot from `auth.policy`.
pub(crate) fn mint_policy_from_auth(
    auth: Option<&crate::config::AuthCfg>,
) -> crate::governance::mint_policy::MintPolicy {
    use crate::governance::mint_policy::{MintPolicy, RoleCeiling};
    let Some(policy) = auth.map(|a| &a.policy) else {
        return MintPolicy::default();
    };
    let modes_to_wire = |m: &Option<Vec<crate::config::BindingMode>>| {
        m.as_ref()
            .map(|list| list.iter().map(|b| b.as_str().to_string()).collect())
    };
    let ceilings = policy
        .mint_ceilings
        .iter()
        .map(|(role, c)| {
            (
                role.clone(),
                RoleCeiling {
                    max_ttl_secs: c
                        .max_ttl
                        .as_deref()
                        .and_then(|s| crate::config::parse::parse_duration_secs(s).ok()),
                    allowed_pools: c.allowed_pools.clone(),
                    binding_modes: modes_to_wire(&c.binding_modes),
                },
            )
        })
        .collect();
    MintPolicy {
        self_mint: policy.self_mint,
        block_max_ttl_secs: policy
            .max_ttl
            .as_deref()
            .and_then(|s| crate::config::parse::parse_duration_secs(s).ok()),
        block_binding_modes: modes_to_wire(&policy.binding_modes),
        ceilings,
    }
}

/// `group_provision`: validation messages, written `; `-separated.
struct GroupProvisionJoined<'a>(&'a [String]);

impl std::fmt::Display for GroupProvisionJoined<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, message) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            f.write_str(message)?;
        }
        Ok(())
    }
}

/// `group_provision`: the next App snapshot with one group added and the tree re-validated
/// (operator group changes and mint auto-provisioning, control plane).
pub(crate) fn group_provision_build(
    current: &crate::state::App,
    name: &str,
    cfg: crate::config::GroupCfg,
) -> Result<crate::state::App, crate::config::transaction::TxnError> {
    use crate::config::transaction::TxnError;
    use crate::governance::group_provision::{pool_known, MAX_GROUP_NAME_LEN};
    if name.trim().is_empty() {
        return Err(TxnError::Validation("group name must not be empty".into()));
    }
    if name.len() > MAX_GROUP_NAME_LEN {
        return Err(TxnError::Validation(format!(
            "group name is {} chars; must be <= {MAX_GROUP_NAME_LEN}",
            name.len()
        )));
    }

    let mut groups = current.groups_registry.clone();
    groups.insert(name.to_string(), cfg);
    let mut errors = Vec::new();
    crate::config::groups::validate_groups(&groups, &|p| pool_known(current, p), &mut errors);
    if !errors.is_empty() {
        return Err(TxnError::Validation(format!(
            "invalid group `{name}`: {}",
            GroupProvisionJoined(&errors)
        )));
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.cost = std::sync::Arc::new(next.cost.with_groups(&groups));
    next.groups_registry = groups;
    Ok(next)
}

/// `self_serve`: a self-serve key id, derived once per self-serve mint (control plane).
pub(crate) fn self_serve_key_id(prefix: &str, tag: &[u8]) -> String {
    format!("{prefix}{}", hex::encode(tag))
}

/// `self_serve`: a self-serve binding's display name, once per binding write.
pub(crate) fn self_serve_binding_name(user_sub: &str) -> String {
    format!("self-serve key ({user_sub})")
}

/// `self_serve`: a fresh self-serve binding's group, once per binding write.
pub(crate) fn self_serve_group(prefix: &str, user_sub: &str) -> String {
    format!("{prefix}{user_sub}")
}

/// `self_serve`: a binding field owned once per binding write (subject, mode, provider).
pub(crate) fn self_serve_owned(text: &str) -> String {
    text.to_owned()
}

use crate::governance::BudgetCell;
use crate::persistence::observations::BudgetTotal;

/// `native_runtime`: each scraped bucket's usage cell and its (bucket, window), read in bucket
/// order (the /metrics scrape).
pub(crate) async fn native_runtime_scrape_cells<'b>(
    state: &crate::governance::GovState,
    buckets: &[(&'b str, &str)],
    now: u64,
) -> RecordStoreResult<(Vec<BudgetCell>, Vec<(&'b str, u64)>)> {
    let mut cells = Vec::with_capacity(buckets.len());
    let mut windows = Vec::with_capacity(buckets.len());
    for (id, period) in buckets {
        let window = crate::governance::budget_window(period, now);
        cells.push(state.bucket_cell_async(id, window).await?);
        windows.push((*id, window));
    }
    Ok((cells, windows))
}

/// `native_runtime`: one scrape view per bucket, from its cell and observation total (the
/// /metrics scrape).
pub(crate) fn native_runtime_scrape_views<T>(
    buckets: &[(&str, &str)],
    cells: Vec<BudgetCell>,
    observed: Vec<BudgetTotal>,
    mut view: impl FnMut(&str, &str, BudgetCell, BudgetTotal) -> RecordStoreResult<T>,
) -> RecordStoreResult<Vec<T>> {
    buckets
        .iter()
        .zip(cells)
        .zip(observed)
        .map(|((&(id, period), cell), observed)| view(id, period, cell, observed))
        .collect()
}

/// `native_runtime`: observation totals for many (bucket, window) pairs: one store open, one
/// accounting-marker read, budgets read in batches of the store scan limit (admin views and the
/// /metrics scrape).
pub(crate) async fn native_runtime_observation_totals(
    state: &crate::governance::GovState,
    core: &std::sync::Arc<crate::persistence::facade::CoreStore>,
    buckets: &[(&str, u64)],
) -> RecordStoreResult<Vec<BudgetTotal>> {
    use crate::persistence::observations::ObservationStore;
    let none = || buckets.iter().map(|_| BudgetTotal::default()).collect();
    if buckets.is_empty() || !ObservationStore::supports(core) {
        return Ok(none());
    }
    let store =
        ObservationStore::open(core.clone()).map_err(|e| RecordStoreError::from(e.to_string()))?;
    if !store
        .has_accounting()
        .await
        .map_err(|e| RecordStoreError::from(e.to_string()))?
    {
        return Ok(none());
    }
    let ids: Vec<String> = buckets
        .iter()
        .map(|(bucket, window)| crate::plane_driver::observation_budget_id(bucket, *window))
        .collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let totals = store
        .budgets(&ids)
        .await
        .map_err(|e| RecordStoreError::from(e.to_string()))?;
    for ((bucket, window), total) in buckets.iter().zip(&totals) {
        state.cache_observation_total(bucket, *window, total.clone());
    }
    Ok(totals)
}

/// `native_runtime`: one bucket's per-model lane totals, the cell's model counts plus the observed
/// lanes (admin views and the /metrics scrape).
pub(crate) fn native_runtime_model_lanes<'a>(
    models: impl Iterator<Item = (&'a str, &'a std::collections::BTreeMap<String, Count>)> + Clone,
    observed: &BudgetTotal,
) -> RecordStoreResult<Vec<(String, std::collections::BTreeMap<String, Count>)>> {
    use std::collections::BTreeMap;
    let overflow = std::cell::Cell::new(false);
    let models = models.map(|(lane, cur)| (lane, cur.clone()));
    let by_lane = busbar_kernel_ledger::usage::by_lane(models, |a, b| {
        a.checked_add(b).unwrap_or_else(|_| {
            overflow.set(true);
            Count::ZERO
        })
    });
    if overflow.get() {
        return Err(RecordStoreError("lane count total overflow".into()));
    }
    let mut by_lane: BTreeMap<String, BTreeMap<String, Count>> = by_lane.into_iter().collect();
    for (lane, units) in &observed.units {
        let counts = by_lane.entry(lane.clone()).or_default();
        for (class, count) in units {
            let entry = counts.entry(class.clone()).or_default();
            *entry = entry
                .checked_add(*count)
                .map_err(|_| RecordStoreError("observation lane count overflow".into()))?;
        }
    }
    Ok(by_lane.into_iter().collect())
}
