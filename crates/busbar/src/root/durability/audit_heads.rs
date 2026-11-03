// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::sdk::store::conditional::{
    Decision, Expected, Mutation, Predicate, Request,
};
use busbar_contract::store_calls::StoreCalls;
use busbar_kernel_audit::{heads::HEAD_SAMPLE_SECONDS, HeadHistory, SignedHead};
use busbar_kernel_wal::{JournalRecord, Record};
use serde::{Deserialize, Serialize};

use super::store_chain::{wait_for, JOURNAL_SCHEMA};
use super::store_identity::HeldLease;

pub(super) const SCHEMA: &str = "busbar.audit.heads.v1";
const PAGE: u32 = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    seq: u64,
    hash: String,
    signature: Option<String>,
    key_id: Option<String>,
    wall: u64,
}

impl From<SignedHead> for Head {
    fn from(h: SignedHead) -> Self {
        Self {
            seq: h.seq,
            hash: h.hash,
            signature: h.signature,
            key_id: h.key_id,
            wall: h.wall,
        }
    }
}

impl Head {
    fn signed(&self) -> SignedHead {
        SignedHead {
            seq: self.seq,
            hash: self.hash.clone(),
            signature: self.signature.clone(),
            key_id: self.key_id.clone(),
            wall: self.wall,
        }
    }

    fn validate(&self) -> Result<(), String> {
        let hex = |s: &str, n| {
            s.len() == n
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self.seq == 0
            || !hex(&self.hash, 64)
            || self.signature.is_some() != self.key_id.is_some()
            || self.signature.as_ref().is_some_and(|s| !hex(s, 128))
            || self.key_id.as_ref().is_some_and(|s| !hex(s, 16))
        {
            return Err("invalid persisted audit head".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    #[serde(rename = "v")]
    version: u8,
    #[serde(rename = "t")]
    tip: Head,
    #[serde(rename = "s")]
    last_sample_seq: u64,
    #[serde(rename = "w")]
    last_sample_wall: u64,
    #[serde(rename = "n")]
    samples: u64,
}

fn tip_key(node: u64) -> Vec<u8> {
    [node.to_be_bytes().as_slice(), &[1]].concat()
}

fn sample_prefix(node: u64) -> Vec<u8> {
    [node.to_be_bytes().as_slice(), &[0]].concat()
}

fn sample_key(node: u64, seq: u64) -> Vec<u8> {
    [sample_prefix(node), seq.to_be_bytes().to_vec()].concat()
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let bytes =
        serde_json::to_vec(value).map_err(|e| format!("audit head cannot be encoded: {e}"))?;
    if bytes.len() > busbar_contract::MAX_RECORD_BYTES {
        return Err("audit head exceeds the Store record bound".into());
    }
    Ok(bytes)
}

fn checkpoint(calls: &dyn StoreCalls, node: u64) -> Result<Option<(Checkpoint, Vec<u8>)>, String> {
    let Some(raw) =
        wait_for(calls.record_get(SCHEMA, &tip_key(node))).map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let checkpoint: Checkpoint = serde_json::from_slice(raw.as_slice())
        .map_err(|_| "the persisted audit checkpoint cannot be decoded")?;
    checkpoint.tip.validate()?;
    if checkpoint.version != 1
        || checkpoint.samples == 0
        || checkpoint.last_sample_seq == 0
        || checkpoint.last_sample_seq > checkpoint.tip.seq
        || checkpoint.last_sample_seq == checkpoint.tip.seq
            && checkpoint.last_sample_wall != checkpoint.tip.wall
    {
        return Err("invalid persisted audit checkpoint".into());
    }
    Ok(Some((checkpoint, raw.as_slice().to_vec())))
}

fn samples(calls: &dyn StoreCalls, node: u64) -> Result<Vec<Head>, String> {
    let mut pending = vec![sample_prefix(node)];
    let mut rows = Vec::new();
    while let Some(prefix) = pending.pop() {
        let page = wait_for(calls.record_scan(SCHEMA, &prefix, PAGE)).map_err(|e| e.to_string())?;
        if page.len() > PAGE as usize
            || page
                .iter()
                .any(|(k, _)| k.len() != 17 || !k.starts_with(&prefix))
            || page.windows(2).any(|p| p[0].0 >= p[1].0)
        {
            return Err("invalid persisted audit sample page".into());
        }
        if page.len() < PAGE as usize {
            rows.extend(page);
        } else {
            if prefix.len() >= 17 {
                return Err("oversized persisted audit sample page".into());
            }
            for byte in (0..=u8::MAX).rev() {
                let mut child = prefix.clone();
                child.push(byte);
                pending.push(child);
            }
        }
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows.into_iter()
        .map(|(key, raw)| {
            let head: Head = serde_json::from_slice(raw.as_slice())
                .map_err(|_| "an audit sample cannot be decoded")?;
            head.validate()?;
            if sample_key(node, head.seq) != key {
                return Err("an audit sample disagrees with its key".into());
            }
            Ok(head)
        })
        .collect()
}

pub(super) fn load(calls: &dyn StoreCalls, node: u64) -> Result<Option<HeadHistory>, String> {
    let Some((checkpoint, _)) = checkpoint(calls, node)? else {
        return Ok(None);
    };
    let samples = samples(calls, node)?;
    if samples.len() as u64 != checkpoint.samples
        || samples.last().is_none_or(|head| {
            head.seq != checkpoint.last_sample_seq || head.wall != checkpoint.last_sample_wall
        })
    {
        return Err("persisted audit checkpoint is missing a sample".into());
    }
    HeadHistory::from_retained(
        samples.iter().map(Head::signed).collect(),
        Some(checkpoint.tip.signed()),
    )
    .map(Some)
    .map_err(str::to_string)
}

#[cfg(test)]
pub(super) fn initialize(
    calls: &dyn StoreCalls,
    node: u64,
    records: &[JournalRecord],
) -> Result<HeadHistory, String> {
    initialize_fenced(calls, node, records, &HeldLease::default())
}

pub(super) fn initialize_fenced(
    calls: &dyn StoreCalls,
    node: u64,
    records: &[JournalRecord],
    lease: &HeldLease,
) -> Result<HeadHistory, String> {
    let mut observed = Vec::new();
    for record in records {
        if record.class != busbar_kernel_wal::RecordClass::Transaction {
            continue;
        }
        if let Some(head) = busbar_kernel_audit::journal::head_from_journal_body(&record.body)? {
            if head.node != node || record.node != node {
                return Err("audit and journal node identities disagree".into());
            }
            Head::from(head.head.clone()).validate()?;
            if let Some(last) = observed.last() {
                let last: &busbar_kernel_audit::journal::JournalHead = last;
                if last.head.seq.checked_add(1) != Some(head.head.seq)
                    || last.head.hash != head.prev_hash
                {
                    return Err("audit head metadata has a broken link".into());
                }
            }
            observed.push(head);
        }
    }
    if let Some(history) = load(calls, node)? {
        let anchors = history.anchors();
        let by_seq: std::collections::BTreeMap<_, _> =
            anchors.iter().map(|head| (head.seq, head)).collect();
        for record in &observed {
            if by_seq
                .get(&record.head.seq)
                .is_some_and(|head| **head != record.head)
            {
                return Err("retained audit sample contradicts its journal record".into());
            }
        }
        if let Some(last) = observed.last() {
            if history.tip().is_none_or(|tip| {
                last.head.seq > tip.seq || last.head.seq == tip.seq && last.head != *tip
            }) {
                return Err("retained audit head disagrees with the journal".into());
            }
        }
        return Ok(history);
    }
    if observed
        .first()
        .is_some_and(|first| first.head.seq != 1 || !first.prev_hash.is_empty())
    {
        return Err("an audit backfill requires its complete source chain".into());
    }
    let mut expected: Vec<Head> = Vec::new();
    for record in &observed {
        if expected
            .last()
            .is_none_or(|last| record.head.wall.saturating_sub(last.wall) >= HEAD_SAMPLE_SECONDS)
        {
            expected.push(record.head.clone().into());
        }
    }
    let history = HeadHistory::from_retained(
        expected.iter().map(Head::signed).collect(),
        observed.last().map(|r| r.head.clone()),
    )
    .map_err(str::to_string)?;
    let present = samples(calls, node)?;
    if !expected.starts_with(&present) {
        return Err("an incomplete audit backfill contradicts its journal".into());
    }
    for head in expected.iter().skip(present.len()) {
        backfill_put(
            calls,
            node,
            lease,
            sample_key(node, head.seq),
            encode(head)?,
        )?;
    }
    if let Some(tip) = history.tip() {
        let checkpoint = Checkpoint {
            version: 1,
            tip: tip.clone().into(),
            last_sample_seq: expected
                .last()
                .expect("a nonempty history has a sample")
                .seq,
            last_sample_wall: expected
                .last()
                .expect("a nonempty history has a sample")
                .wall,
            samples: expected.len() as u64,
        };
        backfill_put(calls, node, lease, tip_key(node), encode(&checkpoint)?)?;
    }
    Ok(history)
}

fn backfill_put(
    calls: &dyn StoreCalls,
    node: u64,
    lease: &HeldLease,
    key: Vec<u8>,
    value: Vec<u8>,
) -> Result<(), String> {
    loop {
        let mut predicates = vec![Predicate {
            schema: SCHEMA.into(),
            key: tip_key(node),
            expected: Expected::Absent,
        }];
        if key != tip_key(node) {
            predicates.push(Predicate {
                schema: SCHEMA.into(),
                key: key.clone(),
                expected: Expected::Absent,
            });
        }
        if let Some(fence) = lease.predicate(calls)? {
            predicates.push(fence);
        }
        let request = super::conditional::candidate(
            predicates,
            vec![Mutation::Put {
                schema: SCHEMA.into(),
                key: key.clone(),
                value: value.clone(),
            }],
        );
        match super::conditional::decide(calls, &request)? {
            Decision::Applied => return Ok(()),
            Decision::ConditionConflict => {
                let current =
                    wait_for(calls.record_get(SCHEMA, &key)).map_err(|e| e.to_string())?;
                if current.as_ref().is_some_and(|raw| raw.as_slice() == value) {
                    return Ok(());
                }
                if current.is_some()
                    || wait_for(calls.record_get(SCHEMA, &tip_key(node)))
                        .map_err(|e| e.to_string())?
                        .is_some()
                {
                    return Err("audit checkpoint changed during backfill".into());
                }
            }
        }
    }
}

pub(super) enum Write {
    Ordinary,
    Recorded,
    New(Advance),
}

pub(super) struct Advance {
    node: u64,
    previous: Option<Vec<u8>>,
    next: Checkpoint,
    sample: bool,
    sample_previous: Option<Vec<u8>>,
}

pub(super) fn prepare(calls: &dyn StoreCalls, record: &Record) -> Result<Write, String> {
    let Ok(decoded) = JournalRecord::decode(&record.body) else {
        return Ok(Write::Ordinary);
    };
    if decoded.class != busbar_kernel_wal::RecordClass::Transaction {
        return Ok(Write::Ordinary);
    }
    let Some(audit) = busbar_kernel_audit::journal::head_from_journal_body(&decoded.body)? else {
        return Ok(Write::Ordinary);
    };
    if decoded.node != record.node
        || decoded.node_seq != record.node_seq
        || audit.node != record.node
    {
        return Err("audit and journal node identities disagree".into());
    }
    let head = Head::from(audit.head);
    head.validate()?;
    let (previous, last_sample, count) = match checkpoint(calls, record.node)? {
        Some((old, raw)) => {
            if old.tip == head {
                return Ok(Write::Recorded);
            }
            if old.tip.seq.checked_add(1) != Some(head.seq) || old.tip.hash != audit.prev_hash {
                return Err("audit checkpoint predecessor changed".into());
            }
            (
                Some(raw),
                Some((old.last_sample_seq, old.last_sample_wall)),
                old.samples,
            )
        }
        None if head.seq == 1 && audit.prev_hash.is_empty() => {
            if !wait_for(calls.record_scan(SCHEMA, &sample_prefix(record.node), 1))
                .map_err(|e| e.to_string())?
                .is_empty()
            {
                return Err("audit head backfill has not completed".into());
            }
            (None, None, 0)
        }
        None => return Err("audit checkpoint is absent before a non-genesis record".into()),
    };
    let sample = last_sample
        .as_ref()
        .is_none_or(|last| head.wall.saturating_sub(last.1) >= HEAD_SAMPLE_SECONDS);
    let next = Checkpoint {
        version: 1,
        tip: head.clone(),
        last_sample_seq: if sample {
            head.seq
        } else {
            last_sample.expect("an existing sample").0
        },
        last_sample_wall: if sample {
            head.wall
        } else {
            last_sample.expect("an existing sample").1
        },
        samples: count
            .checked_add(u64::from(sample))
            .ok_or("audit sample count exhausted")?,
    };
    let sample_previous = if sample {
        let raw =
            wait_for(calls.record_get(SCHEMA, &sample_key(record.node, next.last_sample_seq)))
                .map_err(|e| e.to_string())?;
        let raw = raw.map(|v| v.as_slice().to_vec());
        let expected = encode(&next.tip)?;
        if raw.as_ref().is_some_and(|value| value != &expected) {
            return Err("an immutable audit sample already has different bytes".into());
        }
        raw
    } else {
        None
    };
    Ok(Write::New(Advance {
        node: record.node,
        previous,
        next,
        sample,
        sample_previous,
    }))
}

impl Advance {
    pub(super) fn commit(
        self,
        calls: &dyn StoreCalls,
        lease: &HeldLease,
        final_key: Vec<u8>,
        final_value: Vec<u8>,
    ) -> Result<(), String> {
        self.commit_parts(
            calls,
            lease,
            vec![Mutation::Put {
                schema: JOURNAL_SCHEMA.into(),
                key: final_key,
                value: final_value,
            }],
        )
    }

    pub(super) fn parts_fit(&self, parts: &[Mutation], fence: Option<Predicate>) -> bool {
        self.request(parts, fence)
            .is_ok_and(|request| request.encode_held().is_ok())
    }

    fn request(&self, parts: &[Mutation], fence: Option<Predicate>) -> Result<Request, String> {
        let encoded = encode(&self.next)?;
        let mut predicates = vec![Predicate {
            schema: SCHEMA.into(),
            key: tip_key(self.node),
            expected: self
                .previous
                .clone()
                .map_or(Expected::Absent, Expected::Bytes),
        }];
        if let Some(fence) = fence {
            predicates.push(fence);
        }
        let mut mutations = parts.to_vec();
        mutations.push(Mutation::Put {
            schema: SCHEMA.into(),
            key: tip_key(self.node),
            value: encoded,
        });
        if self.sample {
            predicates.push(Predicate {
                schema: SCHEMA.into(),
                key: sample_key(self.node, self.next.last_sample_seq),
                expected: self
                    .sample_previous
                    .clone()
                    .map_or(Expected::Absent, Expected::Bytes),
            });
            mutations.push(Mutation::Put {
                schema: SCHEMA.into(),
                key: sample_key(self.node, self.next.last_sample_seq),
                value: encode(&self.next.tip)?,
            });
        }
        Ok(super::conditional::candidate(predicates, mutations))
    }

    pub(super) fn commit_parts(
        self,
        calls: &dyn StoreCalls,
        lease: &HeldLease,
        parts: Vec<Mutation>,
    ) -> Result<(), String> {
        let encoded = encode(&self.next)?;
        loop {
            let request = self.request(&parts, lease.predicate(calls)?)?;
            match super::conditional::decide(calls, &request)? {
                Decision::Applied => return Ok(()),
                Decision::ConditionConflict => {
                    let current = wait_for(calls.record_get(SCHEMA, &tip_key(self.node)))
                        .map_err(|e| e.to_string())?;
                    let current = current.map(|v| v.as_slice().to_vec());
                    if current.as_ref() == Some(&encoded) {
                        return Ok(());
                    }
                    if current != self.previous {
                        return Err("audit checkpoint predecessor changed".into());
                    }
                    if self.sample {
                        let sample =
                            wait_for(calls.record_get(
                                SCHEMA,
                                &sample_key(self.node, self.next.last_sample_seq),
                            ))
                            .map_err(|e| e.to_string())?
                            .map(|v| v.as_slice().to_vec());
                        if sample != self.sample_previous {
                            return Err("an immutable audit sample changed".into());
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/audit_heads.rs"]
mod tests;
