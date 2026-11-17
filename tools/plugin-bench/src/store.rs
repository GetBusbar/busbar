// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STORE (v4): commit / read / clock against one opened instance.
//!
//! The instance is opened and its dataset bootstrapped (dataset root + writer admission) through
//! the loader's own `LoadedPersistence`, exactly as core opens it. Measured ops then cross the
//! store's slots inline with frames this module owns.
//!
//! The commit shape is the kernel journal's append: one compare-and-set on a head key (expected =
//! the previous head) plus one record put (`--record-bytes`, default 1 KiB), with a 64-byte
//! result and a fresh attempt id per commit, so every commit leaves one receipt behind, as every
//! request on the real path does. Records rotate over 1024 keys per thread, so the dataset stays
//! bounded and only what the store keeps per commit (its receipts) grows with the call count.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{Blob, Outcome};
use busbar_contract::abi::store::v4 as wire;
use busbar_contract::abi::store::HostBuf;
use busbar_contract::persistence::{
    self as owned, control, Address, AttemptId, Candidate, Decision, ExpectedValue, Mutation,
    PersistenceBackend, Predicate, PreparedCandidate, CANDIDATE_VERSION,
};
use busbar_contract::Secret;
use busbar_plugin_loader::dispatch::{kinds::store_v4::StoreV4, ConnTable, Frame, Plugin};
use busbar_plugin_loader::store_v4::{Limits, LoadedPersistence};

use crate::frames::{input, output};
use crate::stats::Recorder;
use crate::{Config, Scenario, Spec, Target};

const WRITER: [u8; 16] = [7; 16];
const RECORD_KEYS: u64 = 1024;
const HEAD_BYTES: usize = 32;
const RESULT_BYTES: usize = 64;

struct Opened {
    store: LoadedPersistence,
    info: owned::BackendInfo,
}

// SAFETY: the loaded persistence is shared across the bench threads exactly as core shares it
// across its request tasks; the bench only crosses through `Plugin::answer` on it.
unsafe impl Sync for Opened {}
unsafe impl Send for Opened {}

impl Opened {
    fn plugin(&self) -> &Plugin<StoreV4> {
        self.store.plugin()
    }
}

fn limits() -> Limits {
    Limits {
        descriptor_bytes: 32 * 1024 * 1024,
        output_items: 4096,
        output_bytes: 32 * 1024 * 1024,
        decode_bytes: 32 * 1024 * 1024,
    }
}

fn open(cfg: &Config, target: &Target) -> Result<Arc<Opened>, String> {
    let d = crate::dispatcher();
    let plugin =
        crate::load::<StoreV4>(target, crate::bind(&d, "bench-store", ConnTable::NoNeeds))?;
    let settings = cfg.settings.clone().unwrap_or_else(|| b"{}".to_vec());
    let store = crate::block(LoadedPersistence::open(plugin, d, &settings, limits()))
        .map_err(|e| format!("store open: {e}"))?;
    let info = store.info();
    crate::block(bootstrap(&store, info))?;
    Ok(Arc::new(Opened { store, info }))
}

/// Root the dataset and admit the bench's writer, as the kernel's first start does.
async fn bootstrap(store: &LoadedPersistence, info: owned::BackendInfo) -> Result<(), String> {
    let root = Address {
        namespace: control::NAMESPACE.0,
        key: control::DATASET_KEY.to_vec(),
    };
    let writer = Address {
        namespace: control::NAMESPACE.0,
        key: control::writer_key(WRITER).to_vec(),
    };
    let candidate = Candidate {
        id: attempt(info, [0xb0; 16]),
        codec: CANDIDATE_VERSION,
        predicates: vec![
            Predicate {
                address: root.clone(),
                expected: ExpectedValue::Absent,
            },
            Predicate {
                address: writer.clone(),
                expected: ExpectedValue::Absent,
            },
        ],
        mutations: vec![
            Mutation::Put {
                address: root,
                value: Secret::new(
                    control::Dataset {
                        id: info.dataset,
                        writer_epoch: 1,
                    }
                    .encode()
                    .ok_or("dataset control record")?
                    .to_vec(),
                ),
            },
            Mutation::Put {
                address: writer,
                value: Secret::new(
                    control::Writer {
                        retired_through: 0,
                        admitted_through: 1,
                    }
                    .encode()
                    .ok_or("writer control record")?
                    .to_vec(),
                ),
            },
        ],
        time: None,
        result: Secret::new(Vec::new()),
    };
    let prepared = PreparedCandidate::new(candidate).map_err(|e| format!("bootstrap: {e:?}"))?;
    // The writer's first admission (an Absent-predicated control Writer record) is single-shot by its own
    // shape, so it commits self-fenced, as the kernel's first start does; no queue slot is leased.
    let fenced = owned::SelfFenced::check(&prepared)
        .map_err(|_| "bootstrap candidate is not provably single-shot")?;
    match store
        .commit(prepared, owned::CommitKey::self_fenced(&fenced))
        .await
    {
        Ok(Decision::Applied(_)) => Ok(()),
        other => Err(format!("store bootstrap commit: {other:?}")),
    }
}

fn attempt(info: owned::BackendInfo, operation: [u8; 16]) -> AttemptId {
    AttemptId {
        dataset: info.dataset,
        writer_epoch: 1,
        writer: WRITER,
        execution_epoch: 1,
        operation,
    }
}

pub(crate) fn specs(cfg: &Config, target: &Target) -> Result<Vec<Spec>, String> {
    let opened = open(cfg, target)?;
    let record = cfg.record_bytes;
    let (a, b, c) = (opened.clone(), opened.clone(), opened);
    Ok(vec![
        Spec {
            name: format!("store.commit(cas+put {record}B)"),
            ops: vec!["commit"],
            primary: 0,
            make: Box::new(move |t| Ok(Box::new(Commit::new(a.clone(), t, record)?))),
        },
        Spec {
            name: "store.read(2 keys)".into(),
            ops: vec!["read"],
            primary: 0,
            make: Box::new(move |t| Ok(Box::new(Read::new(b.clone(), t, record)?))),
        },
        Spec {
            name: "store.clock".into(),
            ops: vec!["clock"],
            primary: 0,
            make: Box::new(move |_| Ok(Box::new(Clock(c.clone())))),
        },
    ])
}

/// The per-thread keys: a head and 1024 rotating record keys in the thread's own namespace.
fn namespace(thread: usize) -> [u8; 16] {
    let mut ns = *b"bench.store.ns.\0";
    ns[15] = thread as u8;
    ns
}

fn record_key(k: u64, buf: &mut [u8; 12]) {
    buf[..4].copy_from_slice(b"rec-");
    for (i, d) in buf[4..].iter_mut().enumerate() {
        *d = b"0123456789abcdef"[((k >> (4 * (7 - i))) & 0xf) as usize];
    }
}

/// Every buffer one commit lends, allocated once; a commit only rewrites bytes in place.
struct Commit {
    opened: Arc<Opened>,
    thread: usize,
    n: u64,
    ns: [u8; 16],
    head_key: Box<[u8; 4]>,
    rec_key: Box<[u8; 12]>,
    head_prev: Box<[u8; HEAD_BYTES]>,
    head_next: Box<[u8; HEAD_BYTES]>,
    record: Box<[u8]>,
    result: Box<[u8; RESULT_BYTES]>,
    predicates: Box<[wire::Predicate; 1]>,
    mutations: Box<[wire::Mutation; 2]>,
}

impl Commit {
    fn new(opened: Arc<Opened>, thread: usize, record: usize) -> Result<Self, String> {
        let mut c = Self {
            opened,
            thread,
            n: 0,
            ns: namespace(thread),
            head_key: Box::new(*b"head"),
            rec_key: Box::new([0; 12]),
            head_prev: Box::new([0; HEAD_BYTES]),
            head_next: Box::new([0; HEAD_BYTES]),
            record: vec![0x5a; record].into_boxed_slice(),
            result: Box::new([0xa5; RESULT_BYTES]),
            predicates: Box::new([zero_predicate()]),
            mutations: Box::new([zero_mutation(), zero_mutation()]),
        };
        // The thread's first head: an absent-predicated put, outside the measurement.
        let mut f = c.frame(true);
        let called = c.opened.plugin().answer(wire::slot::COMMIT, &mut f);
        check_commit(called.outcome, &f.out, "first head")?;
        c.advance();
        Ok(c)
    }

    fn advance(&mut self) {
        self.n += 1;
        *self.head_prev = *self.head_next;
        self.head_next[..8].copy_from_slice(&self.n.to_le_bytes());
        record_key(self.n % RECORD_KEYS, &mut self.rec_key);
    }

    fn frame(&mut self, first: bool) -> Frame<wire::CommitIn, wire::CommitOut> {
        let addr = |key: &[u8]| wire::Address {
            namespace: self.ns,
            key: wire::Bytes {
                ptr: key.as_ptr(),
                len: key.len(),
            },
        };
        self.predicates[0] = wire::Predicate {
            address: addr(&self.head_key[..]),
            tag: if first {
                wire::PREDICATE_ABSENT
            } else {
                wire::PREDICATE_EXACT
            },
            _reserved: 0,
            expected: if first {
                Blob::ABSENT
            } else {
                crate::frames::octets(&self.head_prev[..])
            },
        };
        self.mutations[0] = wire::Mutation {
            address: addr(&self.head_key[..]),
            tag: wire::MUTATION_PUT,
            _reserved: 0,
            exact_length: 0,
            value: crate::frames::octets(&self.head_next[..]),
        };
        self.mutations[1] = wire::Mutation {
            address: addr(&self.rec_key[..]),
            tag: wire::MUTATION_PUT,
            _reserved: 0,
            exact_length: 0,
            value: crate::frames::octets(&self.record),
        };
        let mut operation = [0u8; 16];
        operation[..8].copy_from_slice(&self.n.to_le_bytes());
        operation[8] = self.thread as u8;
        operation[15] = 0xbe;
        let id = self.opened.info;
        let mut i: wire::CommitIn = input();
        i.candidate = wire::Candidate {
            id: wire::AttemptId {
                dataset: id.dataset.0,
                writer: WRITER,
                operation,
                writer_epoch: 1,
                execution_epoch: 1,
            },
            codec: CANDIDATE_VERSION,
            // The bench stands in for the kernel's persistence facade: each thread leases its own queue slot,
            // and every commit on it carries a strictly larger sequence (the first head is 1).
            slot: self.thread as u32,
            seq: self.n + 1,
            time: wire::TimeGuard {
                flags: 0,
                _reserved: 0,
                not_before: 0,
                before: 0,
            },
            predicates: self.predicates.as_ptr(),
            predicates_len: 1,
            mutations: self.mutations.as_ptr(),
            mutations_len: 2,
            result: crate::frames::octets(&self.result[..]),
        };
        Frame::new(i, output())
    }
}

fn zero_predicate() -> wire::Predicate {
    // SAFETY: a plain C descriptor; all-zero is valid.
    unsafe { std::mem::zeroed() }
}

fn zero_mutation() -> wire::Mutation {
    // SAFETY: a plain C descriptor; all-zero is valid.
    unsafe { std::mem::zeroed() }
}

fn check_commit(outcome: Outcome, out: &wire::CommitOut, what: &str) -> Result<(), String> {
    if outcome == Outcome::Ready && out.code == wire::COMMIT_APPLIED {
        return Ok(());
    }
    Err(format!(
        "commit ({what}) answered {outcome:?} code={} (1 = applied)",
        out.code
    ))
}

impl Scenario for Commit {
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String> {
        let mut f = self.frame(false);
        let plugin = self.opened.plugin();
        let called = rec.time(0, || plugin.answer(wire::slot::COMMIT, &mut f));
        check_commit(called.outcome, &f.out, "measured")?;
        self.advance();
        Ok(())
    }
}

/// Read the thread's head and one record: two addresses, values into lent buffers.
struct Read {
    opened: Arc<Opened>,
    addresses: Box<[wire::Address; 2]>,
    _keys: Box<[[u8; 12]; 2]>,
    items: Box<[wire::ReadValue; 2]>,
    bytes: Box<[u8]>,
}

impl Read {
    fn new(opened: Arc<Opened>, thread: usize, record: usize) -> Result<Self, String> {
        // The read thread's own namespace, given a head and record 1 by one untimed commit.
        let mut seed = Commit::new(opened.clone(), thread + 128, record)?;
        let mut f = seed.frame(false);
        let called = opened.plugin().answer(wire::slot::COMMIT, &mut f);
        check_commit(called.outcome, &f.out, "read seed")?;
        let ns = namespace(thread + 128);
        let mut keys = Box::new([[0u8; 12]; 2]);
        keys[0][..4].copy_from_slice(b"head");
        record_key(1, &mut keys[1]);
        let addr = |key: &[u8]| wire::Address {
            namespace: ns,
            key: wire::Bytes {
                ptr: key.as_ptr(),
                len: key.len(),
            },
        };
        let addresses = Box::new([addr(&keys[0][..4]), addr(&keys[1][..])]);
        let mut r = Self {
            opened,
            addresses,
            _keys: keys,
            // SAFETY: plain C descriptors; all-zero is valid.
            items: Box::new(unsafe { std::mem::zeroed() }),
            bytes: vec![0; record + 4096].into_boxed_slice(),
        };
        let mut f = r.frame();
        let called = r.opened.plugin().answer(wire::slot::READ, &mut f);
        check_read(called.outcome, &f.out)?;
        Ok(r)
    }

    fn frame(&mut self) -> Frame<wire::ReadIn, wire::ReadOut> {
        let mut i: wire::ReadIn = input();
        i.dataset = self.opened.info.dataset.0;
        i.addresses = self.addresses.as_ptr();
        i.addresses_len = self.addresses.len();
        i.values = wire::HostValues {
            items: self.items.as_mut_ptr(),
            items_cap: self.items.len(),
            bytes: HostBuf {
                ptr: self.bytes.as_mut_ptr(),
                cap: self.bytes.len(),
            },
        };
        Frame::new(i, output())
    }
}

fn check_read(outcome: Outcome, out: &wire::ReadOut) -> Result<(), String> {
    if outcome == Outcome::Ready && out.code == wire::READ_VALUES {
        return Ok(());
    }
    Err(format!(
        "read answered {outcome:?} code={} needed_items={} needed_bytes={}",
        out.code, out.needed_items, out.needed_bytes
    ))
}

impl Scenario for Read {
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String> {
        let mut f = self.frame();
        let plugin = self.opened.plugin();
        let called = rec.time(0, || plugin.answer(wire::slot::READ, &mut f));
        check_read(called.outcome, &f.out)
    }
}

/// The store's clock: the cheapest kind op, close to the host crossing's own floor.
struct Clock(Arc<Opened>);

impl Scenario for Clock {
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String> {
        let mut i: wire::ClockIn = input();
        i.dataset = self.0.info.dataset.0;
        let mut f: Frame<wire::ClockIn, wire::ClockOut> = Frame::new(i, output());
        let plugin = self.0.plugin();
        let called = rec.time(0, || plugin.answer(wire::slot::CLOCK, &mut f));
        if called.outcome != Outcome::Ready {
            return Err(format!("clock answered {:?}", called.outcome));
        }
        Ok(())
    }
}
