// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Store request encoders and answer decoders (IF §8.8). Every request is a records buffer in the layout of
//! `kinds::store::store`; every answer is decoded from the records of an OK `Answer`. Each decoder is a thin
//! call over a function of `Records`, so the grammar is testable without a driver.

use std::sync::OnceLock;

use busbar_contract::persistence::{
    self as owned, control, Address, BackendInfo, ClockObservation, CommitKey, DatasetId, Decision,
    Durability, ExpectedValue, Mutation, Page, Predicate, PreparedCandidate, Read, ReadResult,
    Scan,
};
use busbar_contract::plugin::KernelSeal;
use busbar_contract::secure::SecureVec;
use busbar_contract::Secret;
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::kinds::store::store as wire;
use busbar_plugin_abi::records::{tag, Full, Pod, Rec, RecErr, Records, Writer};

type Seal = dyn KernelSeal + Send + Sync;

static SEAL: OnceLock<Box<Seal>> = OnceLock::new();

/// W1-A5. The owner of the kernel's `Secret<Vec<u8>>` values hands the loader no seal through the frozen
/// signatures, so the one that reads a candidate's bytes onto the wire is installed once, by core, before any
/// store commit (an owner question in the W1-A5 handoff). Until then `encode_candidate` writes nothing and
/// answers `Full`. Returns false when a seal was already installed.
pub fn install_seal(seal: Box<Seal>) -> bool {
    SEAL.set(seal).is_ok()
}

/// The wire guard of an optional UTC interval; zero = unguarded.
fn guard(time: Option<owned::TimeGuard>) -> wire::TimeGuard {
    let time = time.unwrap_or(owned::TimeGuard {
        not_before: None,
        before: None,
    });
    wire::TimeGuard {
        flags: if time.not_before.is_some() {
            wire::TIME_NOT_BEFORE
        } else {
            0
        } | if time.before.is_some() {
            wire::TIME_BEFORE
        } else {
            0
        },
        _r: 0,
        not_before: time.not_before.unwrap_or(0),
        before: time.before.unwrap_or(0),
    }
}

fn len32(bytes: &[u8]) -> Result<u32, Full> {
    u32::try_from(bytes.len()).map_err(|_| Full)
}

/// A record whose body is `head`, `key`, then `value`. A value is copied only to join it to its key, into a
/// wiping buffer, because `Writer` takes one tail.
fn keyed(
    w: &mut impl Writer,
    record: u16,
    head: &impl Pod,
    key: &[u8],
    value: &[u8],
) -> Result<(), Full> {
    if value.is_empty() {
        return w.put_pod_tail(record, head, key);
    }
    let mut joined = SecureVec::with_capacity(key.len() + value.len()).map_err(|_| Full)?;
    joined.extend(key).map_err(|_| Full)?;
    joined.extend(value).map_err(|_| Full)?;
    w.put_pod_tail(record, head, joined.as_slice())
}

pub fn encode_read(w: &mut impl Writer, r: &Read) -> Result<(), Full> {
    let head = wire::ReadHead {
        dataset: r.dataset.0,
        guard: guard(r.time),
    };
    w.put_pod(wire::tag::READ_HEAD, &head)?;
    for address in &r.addresses {
        let rec = wire::AddressRec {
            namespace: address.namespace,
        };
        w.put_pod_tail(wire::tag::ADDRESS, &rec, &address.key)?;
    }
    Ok(())
}

pub fn encode_scan(w: &mut impl Writer, s: &Scan) -> Result<(), Full> {
    let flags = if s.after.is_some() {
        wire::SCAN_FLAG_AFTER
    } else {
        0
    } | if s.generation.is_some() {
        wire::SCAN_FLAG_GENERATION
    } else {
        0
    } | if s.allow_change {
        wire::SCAN_FLAG_ALLOW_CHANGE
    } else {
        0
    };
    let head = wire::ScanHead {
        dataset: s.dataset.0,
        namespace: s.namespace.0,
        flags,
        max_rows: u32::try_from(s.max_items).unwrap_or(u32::MAX),
        generation: s.generation.unwrap_or(0),
        max_bytes: u64::try_from(s.max_bytes).unwrap_or(u64::MAX),
    };
    w.put_pod(wire::tag::SCAN_HEAD, &head)?;
    w.put(wire::tag::SCAN_PREFIX, &s.prefix)?;
    if let Some(after) = &s.after {
        w.put(wire::tag::SCAN_AFTER, after)?;
    }
    Ok(())
}

/// One FENCE or PREDICATE record.
fn condition(w: &mut impl Writer, record: u16, p: &Predicate, seal: &Seal) -> Result<(), Full> {
    let none: &[u8] = &[];
    let (kind, expected): (u32, &[u8]) = match &p.expected {
        ExpectedValue::Absent => (wire::PREDICATE_ABSENT, none),
        ExpectedValue::Exact(value) => (wire::PREDICATE_EXACT, value.expose(seal).as_slice()),
    };
    let head = wire::PredicateRec {
        namespace: p.address.namespace,
        tag: kind,
        key_len: len32(&p.address.key)?,
    };
    keyed(w, record, &head, &p.address.key, expected)
}

/// One MUTATION record; a DeleteRange carries its prefix as the key and its length in `exact_length`.
fn mutation(w: &mut impl Writer, m: &Mutation, seal: &Seal) -> Result<(), Full> {
    let none: &[u8] = &[];
    let (kind, namespace, key, value, exact_length): (u32, [u8; 16], &[u8], &[u8], u64) = match m {
        Mutation::Put { address, value } => (
            wire::MUTATION_PUT,
            address.namespace,
            address.key.as_slice(),
            value.expose(seal).as_slice(),
            0,
        ),
        Mutation::Delete(address) => (
            wire::MUTATION_DELETE,
            address.namespace,
            address.key.as_slice(),
            none,
            0,
        ),
        Mutation::DeleteRange {
            namespace,
            prefix,
            exact_key_length,
        } => (
            wire::MUTATION_DELETE_RANGE,
            namespace.0,
            prefix.as_slice(),
            none,
            *exact_key_length,
        ),
    };
    let head = wire::MutationRec {
        namespace,
        tag: kind,
        key_len: len32(key)?,
        exact_length,
    };
    keyed(w, wire::tag::MUTATION, &head, key, value)
}

/// Round 30: CAND_HEAD carries `key`'s slot and seq; the FENCE records are `control::fences(c)` (N9).
pub fn encode_candidate(
    w: &mut impl Writer,
    c: &PreparedCandidate,
    key: &CommitKey,
) -> Result<(), Full> {
    let seal: &Seal = SEAL.get().ok_or(Full)?;
    let candidate = c.candidate();
    let (slot, seq) = key.wire();
    let head = wire::CandHead {
        id: wire::AttemptId {
            dataset: candidate.id.dataset.0,
            writer: candidate.id.writer,
            operation: candidate.id.operation,
            writer_epoch: candidate.id.writer_epoch,
            execution_epoch: candidate.id.execution_epoch,
        },
        codec: candidate.codec,
        slot,
        seq,
        guard: guard(candidate.time),
    };
    w.put_pod(wire::tag::CAND_HEAD, &head)?;
    for fence in &control::fences(c) {
        condition(w, wire::tag::FENCE, fence, seal)?;
    }
    for predicate in &candidate.predicates {
        condition(w, wire::tag::PREDICATE, predicate, seal)?;
    }
    for m in &candidate.mutations {
        mutation(w, m, seal)?;
    }
    w.put(wire::tag::RESULT, candidate.result.expose(seal))
}

/// The `clock` request: the dataset's 16 bytes in one CLOCK record (the tag also names the answer).
pub fn encode_dataset(w: &mut impl Writer, d: &DatasetId) -> Result<(), Full> {
    w.put(wire::tag::CLOCK, &d.0)
}

pub fn decode_read(a: &Answer<'_>, n: usize) -> Result<ReadResult, RecErr> {
    read_values(a.records(), n)
}

/// Rows carry no namespace on the wire and SCAN_STALE is not a page: the L3 adapter calls [`decode_scan`] with
/// the request's namespace. This frozen form fills a zero namespace and reads SCAN_STALE as `RecErr::Size`.
pub fn decode_page(a: &Answer<'_>) -> Result<Page, RecErr> {
    match scan_outcome(a.records(), [0; 16])? {
        ScanOutcome::Page(page) => Ok(page),
        ScanOutcome::Stale => Err(RecErr::Size),
    }
}

/// A `scan` answer: the page, or SCAN_STALE (the continued scan's generation changed).
pub enum ScanOutcome {
    Page(Page),
    Stale,
}

/// `decode_page` without the frozen signature's gaps: the rows' namespace is the request's, and SCAN_STALE is
/// an outcome, not a malformed answer.
pub fn decode_scan(a: &Answer<'_>, namespace: [u8; 16]) -> Result<ScanOutcome, RecErr> {
    scan_outcome(a.records(), namespace)
}

/// Round 30: COMMITTED code 1..=6 -> `Decision::{Applied, ConditionConflict, TimeGuardFailed{observed_at},
/// OpIdConflict, Fenced, Stale}` (f6e2cf05d7 persistence.rs:442-459); core supplies Applied's result from its own
/// candidate (N5); code 0 or ≥ 7 is RecErr::Size.
pub fn decode_decision(a: &Answer<'_>) -> Result<Decision, RecErr> {
    decision(a.records())
}

pub fn decode_clock(a: &Answer<'_>) -> Result<ClockObservation, RecErr> {
    clock(a.records())
}

/// Round 6: the `info` answer (exactly one INFO) as the kernel's BackendInfo; an unknown DUR_* is RecErr::Size.
pub fn decode_info(a: &Answer<'_>) -> Result<BackendInfo, RecErr> {
    info(a.records())
}

/// The next record, skipping the generic `METRIC` records any answer may carry (`decode_metrics` reads them).
fn next<'a>(recs: &mut Records<'a>) -> Result<Option<Rec<'a>>, RecErr> {
    loop {
        match recs.next_rec().transpose()? {
            Some(rec) if rec.tag == tag::METRIC => {}
            other => return Ok(other),
        }
    }
}

/// The next record, which must carry `want`.
fn one<'a>(recs: &mut Records<'a>, want: u16) -> Result<Rec<'a>, RecErr> {
    let rec = next(recs)?.ok_or(RecErr::Truncated)?;
    if rec.tag == want {
        Ok(rec)
    } else {
        Err(RecErr::Unknown(rec.tag))
    }
}

/// Nothing may follow.
fn end(recs: &mut Records<'_>) -> Result<(), RecErr> {
    match next(recs)? {
        None => Ok(()),
        Some(rec) => Err(RecErr::Unknown(rec.tag)),
    }
}

/// A store-authoritative observation: its authority identity is registered, so never all zero.
fn observed(authority: [u8; 16], unix_seconds: u64) -> Result<ClockObservation, RecErr> {
    if authority == [0; 16] {
        return Err(RecErr::Size);
    }
    Ok(ClockObservation {
        authority,
        unix_seconds,
    })
}

fn reserved(r: u32) -> Result<(), RecErr> {
    if r == 0 {
        Ok(())
    } else {
        Err(RecErr::Reserved)
    }
}

fn read_values(mut recs: Records<'_>, n: usize) -> Result<ReadResult, RecErr> {
    let done = one(&mut recs, wire::tag::READ_DONE)?.pod::<wire::ReadDone>()?;
    reserved(done._r)?;
    let observed_at = observed(done.authority, done.observed_at)?;
    match done.code {
        wire::READ_VALUES => {
            let mut values = Vec::with_capacity(n);
            for _ in 0..n {
                let rec = one(&mut recs, wire::tag::VALUE)?;
                let (head, tail) = rec.pod_tail::<wire::ValueRec>()?;
                reserved(head._r)?;
                values.push(match head.found {
                    0 if tail.is_empty() => None,
                    1 => Some(Secret::new(tail.to_vec())),
                    _ => return Err(RecErr::Size),
                });
            }
            end(&mut recs)?;
            Ok(ReadResult::Values {
                observed_at,
                values,
            })
        }
        wire::READ_TIME_GUARD_FAILED => {
            end(&mut recs)?;
            Ok(ReadResult::TimeGuardFailed { observed_at })
        }
        _ => Err(RecErr::Size),
    }
}

fn scan_outcome(mut recs: Records<'_>, namespace: [u8; 16]) -> Result<ScanOutcome, RecErr> {
    let done = one(&mut recs, wire::tag::SCAN_DONE)?.pod::<wire::ScanDone>()?;
    match done.code {
        wire::SCAN_STALE => {
            end(&mut recs)?;
            return Ok(ScanOutcome::Stale);
        }
        wire::SCAN_PAGE => {}
        _ => return Err(RecErr::Size),
    }
    if done.continuation != wire::SCAN_EXHAUSTED && done.continuation != wire::SCAN_CONTINUE {
        return Err(RecErr::Size);
    }
    let mut rows: Vec<(Address, Secret<Vec<u8>>)> = Vec::new();
    let mut next_key = None;
    while let Some(rec) = next(&mut recs)? {
        match rec.tag {
            wire::tag::ROW => {
                let (head, tail) = rec.pod_tail::<wire::RowRec>()?;
                reserved(head._r)?;
                let key_len = usize::try_from(head.key_len).map_err(|_| RecErr::Size)?;
                let (key, value) = tail.split_at_checked(key_len).ok_or(RecErr::Size)?;
                if rows
                    .last()
                    .is_some_and(|(last, _)| last.key.as_slice() >= key)
                {
                    return Err(RecErr::Size);
                }
                rows.push((
                    Address {
                        namespace,
                        key: key.to_vec(),
                    },
                    Secret::new(value.to_vec()),
                ));
            }
            wire::tag::NEXT => {
                next_key = Some(rec.body.to_vec());
                end(&mut recs)?;
                break;
            }
            other => return Err(RecErr::Unknown(other)),
        }
    }
    let following = if done.continuation == wire::SCAN_CONTINUE {
        let named = next_key.ok_or(RecErr::Truncated)?;
        if rows.last().is_none_or(|(last, _)| last.key != named) {
            return Err(RecErr::Size);
        }
        Some(named)
    } else if next_key.is_some() {
        return Err(RecErr::Size);
    } else {
        None
    };
    Ok(ScanOutcome::Page(Page {
        generation: done.generation,
        rows,
        next: following,
    }))
}

fn decision(mut recs: Records<'_>) -> Result<Decision, RecErr> {
    let done = one(&mut recs, wire::tag::COMMITTED)?.pod::<wire::Committed>()?;
    end(&mut recs)?;
    reserved(done._r)?;
    let observed_at = observed(done.authority, done.observed_at)?;
    Ok(match done.code {
        wire::COMMIT_APPLIED => Decision::Applied(Secret::default()),
        wire::COMMIT_CONDITION_CONFLICT => Decision::ConditionConflict,
        wire::COMMIT_TIME_GUARD_FAILED => Decision::TimeGuardFailed { observed_at },
        wire::COMMIT_OPID_CONFLICT => Decision::OpIdConflict,
        wire::COMMIT_FENCED => Decision::Fenced,
        wire::COMMIT_STALE => Decision::Stale,
        _ => return Err(RecErr::Size),
    })
}

fn clock(mut recs: Records<'_>) -> Result<ClockObservation, RecErr> {
    let rec = one(&mut recs, wire::tag::CLOCK)?.pod::<wire::ClockRec>()?;
    end(&mut recs)?;
    observed(rec.authority, rec.observed_at)
}

fn info(mut recs: Records<'_>) -> Result<BackendInfo, RecErr> {
    let rec = one(&mut recs, wire::tag::INFO)?.pod::<wire::InfoRec>()?;
    end(&mut recs)?;
    let durability = match rec.durability {
        wire::DUR_EPHEMERAL => Durability::Ephemeral,
        wire::DUR_LOCAL => Durability::Local,
        wire::DUR_QUORUM => Durability::Quorum,
        _ => return Err(RecErr::Size),
    };
    Ok(BackendInfo {
        dataset: DatasetId(rec.dataset),
        atomic_domain: rec.atomic_domain,
        clock_authority: rec.clock_authority,
        physical_version: rec.physical_version,
        durability,
    })
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
