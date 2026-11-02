// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::sdk::store::conditional::{Expected, Mutation, Predicate};
use busbar_contract::caps::{DurableWrite, Grant, StepName};
use busbar_contract::store_calls::StoreCalls;
use busbar_kernel::governance::recovery::{RecoveryError, RecoveryEvent, RecoverySink};
use busbar_kernel_wal::{BodyReader, BodyWriter, Entry, JournalRecord, Record, RecordClass};
use serde::{Deserialize, Serialize};

use super::store_chain::{off_runtime, read_chain, wait_for, ACK_DEADLINE};
use super::{Durability, JournalLane};

pub(crate) const HEAD_SCHEMA: &str = "busbar.usage-recovery-head.v1";
const TAG: &str = "usage.recovery.v1";
const PAGE: u32 = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u8,
    node: u64,
    sequence: u64,
    revision: u64,
    event_digest: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    event: RecoveryEvent,
    previous_head: Option<Head>,
}

fn unavailable(why: impl ToString) -> RecoveryError {
    RecoveryError::Unavailable(why.to_string())
}

fn invalid(why: impl ToString) -> RecoveryError {
    RecoveryError::Invalid(why.to_string())
}

fn body(candidate: &Candidate) -> Result<Vec<u8>, RecoveryError> {
    let encoded = serde_json::to_vec(candidate).map_err(invalid)?;
    let mut writer = BodyWriter::new();
    writer.text(TAG).bytes(&encoded);
    Ok(writer.finish())
}

fn candidate(record: &JournalRecord) -> Result<Option<Candidate>, RecoveryError> {
    if record.class != RecordClass::Reconciliation {
        return Ok(None);
    }
    let mut reader = BodyReader::new(&record.body);
    if reader.text() != Some(TAG) {
        return Ok(None);
    }
    let encoded = reader
        .bytes()
        .ok_or_else(|| invalid("truncated recovery candidate"))?;
    if !reader.is_done() {
        return Err(invalid("trailing recovery candidate bytes"));
    }
    serde_json::from_slice(encoded).map(Some).map_err(invalid)
}

pub(super) fn is_recovery_record(record: &Record) -> bool {
    JournalRecord::decode(&record.body).is_ok_and(|record| {
        record.class == RecordClass::Reconciliation
            && BodyReader::new(&record.body).text() == Some(TAG)
    })
}

fn head(
    calls: &dyn StoreCalls,
    operation: &[u8; 16],
) -> Result<Option<(Head, Vec<u8>)>, RecoveryError> {
    let Some(raw) = wait_for(calls.record_get(HEAD_SCHEMA, operation)).map_err(unavailable)? else {
        return Ok(None);
    };
    let decoded: Head = serde_json::from_slice(raw.as_slice()).map_err(invalid)?;
    if decoded.version != 1 || decoded.node == 0 || decoded.sequence == 0 {
        return Err(invalid("invalid recovery selection head"));
    }
    Ok(Some((decoded, raw.as_slice().to_vec())))
}

type Chains = BTreeMap<u64, Vec<JournalRecord>>;

fn selected(
    calls: &dyn StoreCalls,
    operation: &[u8; 16],
    tip: &Head,
    owner: u64,
    chains: &mut Chains,
) -> Result<Vec<RecoveryEvent>, RecoveryError> {
    let mut next = Some(tip.clone());
    let mut backwards = Vec::new();
    while let Some(at) = next {
        if at.version != 1 || at.node != owner || at.sequence == 0 {
            return Err(invalid("invalid recovery predecessor pointer"));
        }
        if !chains.contains_key(&at.node) {
            let records = read_chain(calls, at.node).map_err(unavailable)?;
            let decoded = busbar_kernel_wal::decode_run(&records).map_err(invalid)?;
            busbar_kernel_wal::verify_journal(&decoded).map_err(invalid)?;
            chains.insert(at.node, decoded);
        }
        let record = chains[&at.node]
            .iter()
            .find(|record| record.node == at.node && record.node_seq == at.sequence)
            .ok_or_else(|| invalid("selected recovery journal record is missing"))?;
        let candidate = candidate(record)?
            .ok_or_else(|| invalid("selected journal record is not a recovery candidate"))?;
        if &candidate.event.operation_id != operation
            || candidate.event.revision != at.revision
            || candidate.event.fingerprint()? != at.event_digest
        {
            return Err(invalid("selected recovery record identity differs"));
        }
        match &candidate.previous_head {
            Some(previous)
                if previous.revision.checked_add(1) == Some(at.revision)
                    && candidate.event.previous_event == Some(previous.event_digest) => {}
            None if at.revision == 0 && candidate.event.previous_event.is_none() => {}
            _ => return Err(invalid("invalid selected recovery predecessor")),
        }
        next = candidate.previous_head;
        backwards.push(candidate.event);
    }
    backwards.reverse();
    for (index, event) in backwards.iter().enumerate() {
        event.follows(index.checked_sub(1).map(|previous| &backwards[previous]))?;
    }
    Ok(backwards)
}

fn heads(calls: &dyn StoreCalls) -> Result<Vec<([u8; 16], Head)>, RecoveryError> {
    let mut pending = vec![Vec::new()];
    let mut out = Vec::new();
    while let Some(prefix) = pending.pop() {
        let page = wait_for(calls.record_scan(HEAD_SCHEMA, &prefix, PAGE)).map_err(unavailable)?;
        if page.len() > PAGE as usize
            || page
                .iter()
                .any(|(key, _)| key.len() != 16 || !key.starts_with(&prefix))
            || page.windows(2).any(|rows| rows[0].0 >= rows[1].0)
        {
            return Err(invalid("invalid recovery head scan"));
        }
        if page.len() == PAGE as usize {
            if prefix.len() >= 16 {
                return Err(invalid("oversized recovery head page"));
            }
            for byte in (0..=u8::MAX).rev() {
                let mut child = prefix.clone();
                child.push(byte);
                pending.push(child);
            }
        } else {
            for (key, value) in page {
                let operation = key
                    .try_into()
                    .map_err(|_| invalid("invalid recovery head key"))?;
                let head: Head = serde_json::from_slice(value.as_slice()).map_err(invalid)?;
                out.push((operation, head));
            }
        }
    }
    out.sort_by_key(|(operation, _)| *operation);
    Ok(out)
}

#[derive(Clone)]
struct Pending {
    event: RecoveryEvent,
    record: Record,
    head: Head,
    predecessor: Option<Vec<u8>>,
}

struct StoreRecovery {
    book: Arc<Mutex<Durability>>,
    token: Grant<DurableWrite>,
    state: Mutex<DriverState>,
}

#[derive(Default)]
struct DriverState {
    pending: BTreeMap<[u8; 16], Pending>,
    driving: BTreeSet<[u8; 16]>,
}

struct Driving<'a> {
    sink: &'a StoreRecovery,
    operation: [u8; 16],
}

impl Drop for Driving<'_> {
    fn drop(&mut self) {
        self.sink
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .driving
            .remove(&self.operation);
    }
}

impl StoreRecovery {
    fn inputs(&self) -> Result<(JournalLane, u64), RecoveryError> {
        let book = self.book.lock().unwrap_or_else(|p| p.into_inner());
        if !book.durable_in_store() {
            return Err(unavailable("recovery requires the opened Store journal"));
        }
        Ok((
            book.lane()
                .cloned()
                .ok_or_else(|| unavailable("no recovery journal lane"))?,
            book.journal.node(),
        ))
    }

    fn persist_at(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if !state.driving.insert(event.operation_id) {
                return Err(unavailable(
                    "this recovery operation already has an active driver",
                ));
            }
        }
        let _driving = Driving {
            sink: self,
            operation: event.operation_id,
        };
        let (lane, node) = self.inputs()?;
        let calls = lane.calls();
        let initial_fences = lane.recovery_predicates(node).map_err(unavailable)?;
        let current = head(calls.as_ref(), &event.operation_id)?;
        let digest = event.fingerprint()?;
        if let Some((current_head, _)) = &current {
            if current_head.node != node {
                return Err(RecoveryError::Conflict(
                    "this recovery operation belongs to another node".into(),
                ));
            }
            if current_head.event_digest == digest {
                let run = selected(
                    calls.as_ref(),
                    &event.operation_id,
                    current_head,
                    node,
                    &mut Chains::new(),
                )?;
                if run.last() != Some(event) {
                    return Err(invalid("recovery event digest collision"));
                }
                if head(calls.as_ref(), &event.operation_id)?
                    .as_ref()
                    .map(|(_, raw)| raw)
                    != current.as_ref().map(|(_, raw)| raw)
                {
                    return Err(RecoveryError::Conflict(
                        "recovery selection advanced during confirmation".into(),
                    ));
                }
                if lane.recovery_predicates(node).map_err(unavailable)? != initial_fences {
                    return Err(unavailable(
                        "the node fence changed during recovery confirmation",
                    ));
                }
                self.state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .pending
                    .remove(&event.operation_id);
                return Ok(());
            }
        }
        let previous = current.as_ref().map(|(head, _)| head);
        let run = previous
            .map(|head| {
                selected(
                    calls.as_ref(),
                    &event.operation_id,
                    head,
                    node,
                    &mut Chains::new(),
                )
            })
            .transpose()?;
        event
            .follows(run.as_ref().and_then(|events| events.last()))
            .map_err(|_| {
                RecoveryError::Conflict(
                    "recovery selection has advanced or names another predecessor".into(),
                )
            })?;
        let predecessor = current.as_ref().map(|(_, raw)| raw.clone());
        let saved = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state
                .pending
                .get(&event.operation_id)
                .is_some_and(|p| p.predecessor != predecessor)
            {
                state.pending.remove(&event.operation_id);
            }
            state.pending.get(&event.operation_id).cloned()
        };
        if saved.as_ref().is_some_and(|p| p.event != *event) {
            return Err(RecoveryError::Conflict(
                "another immutable candidate owns this recovery revision".into(),
            ));
        }
        let candidate = if let Some(saved) = saved {
            saved
        } else {
            let candidate = Candidate {
                event: event.clone(),
                previous_head: previous.cloned(),
            };
            let encoded = body(&candidate)?;
            lane.validate_recovery_frame(node, encoded.len())
                .map_err(invalid)?;
            let sealed = {
                let mut book = self.book.lock().unwrap_or_else(|p| p.into_inner());
                let wall = busbar_kernel::store::now_ms() / 1_000;
                let ack = book
                    .journal
                    .append(
                        &self.token,
                        StepName::Meter,
                        &[Entry::new(RecordClass::Reconciliation, encoded).at(wall, 0)],
                    )
                    .map_err(|_| {
                        unavailable("recovery candidate remains unconfirmed in the journal")
                    })?;
                ack.sealed
                    .into_iter()
                    .last()
                    .ok_or_else(|| invalid("recovery append sealed no record"))?
            };
            let pending = Pending {
                event: event.clone(),
                head: Head {
                    version: 1,
                    node,
                    sequence: sealed.node_seq,
                    revision: event.revision,
                    event_digest: digest,
                },
                record: Record::new(node, sealed.node_seq, sealed.encode()),
                predecessor: predecessor.clone(),
            };
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pending
                .insert(event.operation_id, pending.clone());
            pending
        };
        if candidate.predecessor != predecessor {
            return Err(RecoveryError::Conflict(
                "recovery predecessor changed before selection".into(),
            ));
        }
        // No usage send, dead transfer, verdict effect or forgetting is authorized until the
        // complete candidate is in the Store AND its operation head selects it.
        let _ = lane.wait_acked(node, candidate.record.node_seq, ACK_DEADLINE);
        lane.confirm_recovery_record(&candidate.record)
            .map_err(unavailable)?;
        let mut predicates = lane.recovery_predicates(node).map_err(unavailable)?;
        predicates.push(Predicate {
            schema: HEAD_SCHEMA.into(),
            key: event.operation_id.to_vec(),
            expected: candidate
                .predecessor
                .clone()
                .map_or(Expected::Absent, Expected::Bytes),
        });
        let value = serde_json::to_vec(&candidate.head).map_err(invalid)?;
        let request = super::conditional::candidate(
            predicates.clone(),
            vec![Mutation::Put {
                schema: HEAD_SCHEMA.into(),
                key: event.operation_id.to_vec(),
                value: value.clone(),
            }],
        );
        drop(request.encode_held().map_err(invalid)?);
        // Selection heads only advance and are never deleted or restored. A later attempt may
        // use a fresh conditional id for this exact prior-row -> immutable-candidate CAS: the
        // full prior predicate prevents replaying an effect or replacing a winning branch even
        // after conditional receipt retention expires. This does not renew a usage operation.
        let decision = wait_for(calls.record_transaction(&request));
        let observed = head(calls.as_ref(), &event.operation_id)?;
        if let Some((selected_head, selected_raw)) = &observed {
            if selected_head.node == node && selected_head.event_digest == digest {
                if selected_raw != &value {
                    let run = selected(
                        calls.as_ref(),
                        &event.operation_id,
                        selected_head,
                        node,
                        &mut Chains::new(),
                    )?;
                    if run.last() != Some(event) {
                        return Err(invalid("recovery event digest collision"));
                    }
                }
                if lane
                    .recovery_predicates(node)
                    .map_err(unavailable)?
                    .as_slice()
                    == &predicates[..predicates.len() - 1]
                {
                    self.state
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .pending
                        .remove(&event.operation_id);
                    return Ok(());
                }
            }
        }
        if observed.as_ref().map(|(_, raw)| raw) != candidate.predecessor.as_ref() {
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pending
                .remove(&event.operation_id);
            return Err(RecoveryError::Conflict(
                "another recovery candidate won selection".into(),
            ));
        }
        Err(unavailable(format!(
            "recovery head selection is unconfirmed: {decision:?}"
        )))
    }
}

impl RecoverySink for StoreRecovery {
    fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        off_runtime(|| self.persist_at(event))
    }

    fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        off_runtime(|| {
            let (lane, node) = self.inputs()?;
            let predicates = lane.recovery_predicates(node).map_err(unavailable)?;
            let calls = lane.calls();
            let mut chains = Chains::new();
            let mut events = Vec::new();
            for (operation, tip) in heads(calls.as_ref())? {
                if tip.node == node {
                    events.extend(selected(
                        calls.as_ref(),
                        &operation,
                        &tip,
                        node,
                        &mut chains,
                    )?);
                }
            }
            if lane.recovery_predicates(node).map_err(unavailable)? != predicates {
                return Err(unavailable(
                    "the local node fence changed during recovery replay",
                ));
            }
            Ok(events)
        })
    }
}

pub(crate) fn usage_recovery_sink(book: &Arc<Mutex<Durability>>) -> Arc<dyn RecoverySink> {
    Arc::new(StoreRecovery {
        book: Arc::clone(book),
        token: busbar_kernel::teller::Kernel::new().durability_token(),
        state: Mutex::new(DriverState::default()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::store_double::RecordSlots;
    use busbar_kernel::governance::recovery::{RecoveryKind, RecoveryState};

    fn opened(slots: &RecordSlots, host: &str) -> Arc<Mutex<Durability>> {
        let taken = super::super::take_node(slots.calls().as_ref(), host).unwrap();
        let lane = JournalLane::start(slots.calls(), "recovery-test").unwrap();
        if let Some(lease) = taken.lease {
            lane.hold_lease(lease);
        }
        lane.bind_recovery_identity(host, taken.id).unwrap();
        Arc::new(Mutex::new(
            super::super::build_on_store(
                &super::super::DurabilityConfig { data_dir: None },
                taken.id,
                lane,
                None,
            )
            .unwrap(),
        ))
    }

    fn intent() -> RecoveryEvent {
        RecoveryEvent {
            operation_id: [1; 16],
            revision: 0,
            previous_event: None,
            kind: RecoveryKind::Usage,
            body_fingerprint: [2; 32],
            state: RecoveryState::Intent,
            first_sent_at_ms: Some(1_000),
            payload: vec![3; 900],
        }
    }

    fn transition(previous: &RecoveryEvent, state: RecoveryState) -> RecoveryEvent {
        RecoveryEvent {
            revision: previous.revision + 1,
            previous_event: Some(previous.fingerprint().unwrap()),
            state,
            ..previous.clone()
        }
    }

    #[test]
    fn restart_replays_selected_candidates_with_the_original_send_time() {
        let slots = RecordSlots::new();
        let book = opened(&slots, "recovery-restart");
        let sink = usage_recovery_sink(&book);
        let sent = intent();
        let dead = transition(&sent, RecoveryState::LandedUnknown);
        sink.persist(&sent).unwrap();
        sink.persist(&dead).unwrap();
        let lane = book.lock().unwrap().lane().unwrap().clone();
        assert!(lane.drain(ACK_DEADLINE));
        lane.release_held_lease();
        let restarted = opened(&slots, "recovery-restart");
        assert_eq!(
            usage_recovery_sink(&restarted).replay().unwrap(),
            vec![sent, dead]
        );
    }

    #[test]
    fn two_verdict_callers_select_only_one_candidate_and_forks_are_inert() {
        let slots = RecordSlots::new();
        let book = opened(&slots, "recovery-verdict-race");
        let first = usage_recovery_sink(&book);
        let second = usage_recovery_sink(&book);
        let sent = intent();
        let dead = transition(&sent, RecoveryState::LandedUnknown);
        first.persist(&sent).unwrap();
        first.persist(&dead).unwrap();
        let landed = transition(&dead, RecoveryState::VerdictLanded);
        let not_landed = transition(&dead, RecoveryState::VerdictNotLanded);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let join = Arc::clone(&barrier);
        slots.on_transaction(move |request| {
            if request
                .mutations
                .iter()
                .any(|m| m.address().0 == HEAD_SCHEMA)
            {
                join.wait();
            }
            None
        });
        let one = std::thread::spawn(move || first.persist(&landed));
        let two = std::thread::spawn(move || second.persist(&not_landed));
        let results = [one.join().unwrap(), two.join().unwrap()];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(RecoveryError::Conflict(_))))
                .count(),
            1
        );
        let run = usage_recovery_sink(&book).replay().unwrap();
        assert_eq!(run.len(), 3);
        assert_eq!(run[0], sent);
        assert_eq!(run[1], dead);
        assert!(matches!(
            run[2].state,
            RecoveryState::VerdictLanded | RecoveryState::VerdictNotLanded
        ));
    }

    #[test]
    fn unknown_head_write_keeps_one_candidate_and_retries_only_its_exact_cas() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let slots = RecordSlots::new();
        let book = opened(&slots, "recovery-head-unknown");
        let sink = usage_recovery_sink(&book);
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        slots.on_transaction(move |request| {
            if request
                .mutations
                .iter()
                .any(|m| m.address().0 == HEAD_SCHEMA)
                && seen.fetch_add(1, Ordering::Relaxed) == 0
            {
                return Some(busbar_contract::store_calls::StoreFailure::Failed(
                    "unknown".into(),
                ));
            }
            None
        });
        let sent = intent();
        assert!(matches!(
            sink.persist(&sent),
            Err(RecoveryError::Unavailable(_))
        ));
        let sequence = book.lock().unwrap().journal.next_seq();
        sink.persist(&sent).unwrap();
        assert_eq!(book.lock().unwrap().journal.next_seq(), sequence);
        assert_eq!(sink.replay().unwrap(), vec![sent]);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn fresh_node_mode_is_bound_to_its_minted_registry_row() {
        let slots = RecordSlots::new();
        let first = opened(&slots, "recovery-fresh");
        let fresh = opened(&slots, "recovery-fresh");
        assert_ne!(
            first.lock().unwrap().journal.node(),
            fresh.lock().unwrap().journal.node()
        );
        let sink = usage_recovery_sink(&fresh);
        sink.persist(&intent()).unwrap();
        assert_eq!(sink.replay().unwrap(), vec![intent()]);
    }

    #[test]
    fn lost_acks_confirm_both_candidates_and_the_selected_head() {
        let slots = RecordSlots::new();
        let book = opened(&slots, "recovery-lost-acks");
        let sink = usage_recovery_sink(&book);
        slots.lose_transaction_acks(true);
        sink.persist(&intent()).unwrap();
        assert_eq!(sink.replay().unwrap(), vec![intent()]);
    }

    #[test]
    fn two_live_nodes_cannot_restore_or_resolve_one_anothers_operations() {
        let slots = RecordSlots::new();
        let first = opened(&slots, "recovery-node-one");
        let second = opened(&slots, "recovery-node-two");
        let one = usage_recovery_sink(&first);
        let two = usage_recovery_sink(&second);
        let sent = intent();
        let dead = transition(&sent, RecoveryState::LandedUnknown);
        let verdict = transition(&dead, RecoveryState::VerdictLanded);
        one.persist(&sent).unwrap();
        one.persist(&dead).unwrap();
        let before = second.lock().unwrap().journal.next_seq();
        assert_eq!(two.replay().unwrap(), Vec::<RecoveryEvent>::new());
        assert!(matches!(
            two.persist(&verdict),
            Err(RecoveryError::Conflict(_))
        ));
        assert_eq!(second.lock().unwrap().journal.next_seq(), before);
        one.persist(&verdict).unwrap();
        assert!(matches!(
            one.persist(&dead),
            Err(RecoveryError::Conflict(_))
        ));
        assert_eq!(one.replay().unwrap(), vec![sent, dead, verdict]);
    }

    #[test]
    fn a_pending_head_call_does_not_hold_the_driver_map_or_block_another_operation() {
        let slots = RecordSlots::new();
        let book = opened(&slots, "recovery-independent");
        let sink = usage_recovery_sink(&book);
        let (entered, waiting) = std::sync::mpsc::channel();
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let gate = Arc::clone(&release);
        slots.on_transaction(move |request| {
            if request
                .mutations
                .iter()
                .any(|m| m.address() == (HEAD_SCHEMA, &[1; 16][..]))
            {
                entered.send(()).unwrap();
                let (lock, ready) = &*gate;
                let mut open = lock.lock().unwrap();
                while !*open {
                    open = ready.wait(open).unwrap();
                }
            }
            None
        });
        let first = Arc::clone(&sink);
        let one = std::thread::spawn(move || first.persist(&intent()));
        waiting
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let (finished, done) = std::sync::mpsc::channel();
        let second = Arc::clone(&sink);
        let two = std::thread::spawn(move || {
            let mut event = intent();
            event.operation_id = [4; 16];
            let result = second.persist(&event);
            finished.send(result).unwrap();
        });
        let independent = done.recv_timeout(std::time::Duration::from_secs(5));
        let (lock, ready) = &*release;
        *lock.lock().unwrap() = true;
        ready.notify_all();
        one.join().unwrap().unwrap();
        two.join().unwrap();
        independent
            .expect("unrelated operation must finish while the first Store call is pending")
            .unwrap();
    }
}
