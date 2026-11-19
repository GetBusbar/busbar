// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STORE (MIN-3): commit / read / clock against one opened native store instance.
//!
//! A store is a MIN-3 image. It is admitted from its cdylib (`--plugin`), opened through the
//! loader's `Registry::open_store` (`test_host::NativeStores`) and its dataset initialized, exactly
//! as core opens and starts it. Measured ops are the store adapter's `PersistenceBackend` calls, the
//! path every kernel commit, read and clock takes: the codec, one host crossing and the decode.
//!
//! The commit shape is the kernel journal's append: one compare-and-set on a head key (expected =
//! the previous head) plus one record put (1 KiB), with a 64-byte result and a fresh attempt id per
//! commit, so every commit leaves one receipt behind. Records rotate over 1024 keys per thread, so
//! the dataset stays bounded and only what the store keeps per commit (its receipts) grows.

use std::sync::Arc;

use busbar_contract::persistence::{
    self as owned, Address, AttemptId, Candidate, CommitKey, Decision, ExpectedValue, Mutation,
    PersistenceBackend, Predicate, PreparedCandidate, Read as ReadRequest, ReadResult,
    CANDIDATE_VERSION,
};
use busbar_contract::Secret;
use busbar_plugin_loader::test_host::NativeStores;

use crate::stats::Recorder;
use crate::{Config, Scenario, Spec, Target};

const WRITER: [u8; 16] = [7; 16];
const RECORD_KEYS: u64 = 1024;
const RECORD_BYTES: usize = 1024;
const HEAD_BYTES: usize = 32;
const RESULT_BYTES: usize = 64;

/// The opened instance and the registry that owns it (dropped last).
struct Opened {
    backend: Arc<dyn PersistenceBackend>,
    info: owned::BackendInfo,
    _stores: NativeStores,
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("a bench runtime: {e}"))
}

/// Admit the native image at `target`, open it under `--settings` and initialize its dataset.
fn open(cfg: &Config, target: &Target) -> Result<Arc<Opened>, String> {
    use busbar_plugin_loader::test_host::{admit_bytes, test_sign, TEST_PUBLISHER};
    let Target::Dropped(path) = target else {
        return Err("a native store is benched from its cdylib: pass --plugin <path>".into());
    };
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let (name, version, former) = busbar_plugin_loader::pack_native::identity(&bytes)
        .map_err(|e| format!("{}: not a MIN-3 store image: {e}", path.display()))?;
    let alias = former
        .first()
        .cloned()
        .ok_or("a native image states its alias among its former_names")?;
    let manifest = busbar_plugin_loader::sign::Manifest {
        name: name.clone(),
        alias,
        kind: "store".into(),
        version,
        publisher: TEST_PUBLISHER.into(),
        ..Default::default()
    };
    let manifest = busbar_plugin_loader::pack_native::complete(&bytes, manifest, None)?;
    let manifest = test_sign(manifest, &bytes);
    let admitted = admit_bytes(&bytes, &manifest, &name).map_err(|e| e.to_string())?;
    let stores = NativeStores::plain(admitted).map_err(|e| e.to_string())?;
    let settings = cfg.settings.clone().unwrap_or_else(|| b"{}".to_vec());
    let spec = busbar_plugin_loader::instance::InstanceSpec {
        purpose: busbar_plugin_loader::instance::OpenPurpose::Canonical,
        identity: &name,
        name: "bench-store",
        config_json: &settings,
        limits: Default::default(),
        public_url: None,
        caller_upstreams: &[],
        store_migration: None,
    };
    let seal: busbar_plugin_loader::instance::StoreSeal =
        Arc::new(|| Box::new(busbar_contract::plugin::TestKernelSeal));
    let rt = runtime()?;
    let backend = rt
        .block_on(stores.open(&spec, seal))
        .map_err(|e| format!("store open: {e:?}"))?
        .backend;
    let info = backend.info();
    rt.block_on(initialize(backend.as_ref()))?;
    Ok(Arc::new(Opened {
        backend,
        info,
        _stores: stores,
    }))
}

/// Root the dataset and admit the bench's writer, as the kernel's first start does.
async fn initialize(backend: &dyn PersistenceBackend) -> Result<(), String> {
    use busbar_contract::persistence::SelfFenced;
    let init = busbar_contract::persistence::conformance::initialization(backend, WRITER, 1);
    let key = CommitKey::self_fenced(
        &SelfFenced::check(&init).map_err(|_| "the initialization is not self-fenced")?,
    );
    match backend.commit(init, key).await {
        Ok(Decision::Applied(_)) => Ok(()),
        other => Err(format!("store initialization commit: {other:?}")),
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
    let (a, b, c) = (opened.clone(), opened.clone(), opened);
    Ok(vec![
        Spec {
            name: format!("store.commit(cas+put {RECORD_BYTES}B)"),
            ops: vec!["commit"],
            primary: 0,
            make: Box::new(move |t| Ok(Box::new(Commit::new(a.clone(), t)?))),
        },
        Spec {
            name: "store.read(2 keys)".into(),
            ops: vec!["read"],
            primary: 0,
            make: Box::new(move |t| Ok(Box::new(Read::new(b.clone(), t)?))),
        },
        Spec {
            name: "store.clock".into(),
            ops: vec!["clock"],
            primary: 0,
            make: Box::new(move |_| Ok(Box::new(Clock::new(c.clone())?))),
        },
    ])
}

/// The per-thread namespace: a head and 1024 rotating record keys.
fn namespace(thread: usize) -> [u8; 16] {
    let mut ns = *b"bench.store.ns.\0";
    ns[15] = thread as u8;
    ns
}

fn record_key(k: u64) -> Vec<u8> {
    format!("rec-{k:08x}").into_bytes()
}

/// One thread's journal-shaped commits under its own queue slot.
struct Commit {
    opened: Arc<Opened>,
    rt: tokio::runtime::Runtime,
    thread: usize,
    n: u64,
    ns: [u8; 16],
    head: Vec<u8>,
    record: Vec<u8>,
}

impl Commit {
    fn new(opened: Arc<Opened>, thread: usize) -> Result<Self, String> {
        let mut c = Self {
            opened,
            rt: runtime()?,
            thread,
            n: 0,
            ns: namespace(thread),
            head: vec![0; HEAD_BYTES],
            record: vec![0x5a; RECORD_BYTES],
        };
        // The thread's first head: an absent-predicated put, outside the measurement.
        let first = c.candidate(true)?;
        let key = c.key()?;
        c.rt.block_on(c.opened.backend.commit(first, key))
            .map_err(|e| format!("first head: {e:?}"))
            .and_then(applied)?;
        Ok(c)
    }

    /// The thread's queue slot and a strictly increasing sequence per commit.
    fn key(&self) -> Result<CommitKey, String> {
        let slot = u32::try_from(self.thread % 64).map_err(|_| "slot")?;
        CommitKey::slotted(
            slot,
            self.n + 1,
            &busbar_contract::caps::SlotSeal::acquire_for_tests(),
        )
        .ok_or_else(|| "a valid queue slot key".into())
    }

    fn candidate(&mut self, first: bool) -> Result<PreparedCandidate, String> {
        let addr = |key: &[u8]| Address {
            namespace: self.ns,
            key: key.to_vec(),
        };
        let previous = self.head.clone();
        self.n += 1;
        self.head[..8].copy_from_slice(&self.n.to_le_bytes());
        let mut operation = [0u8; 16];
        operation[..8].copy_from_slice(&self.n.to_le_bytes());
        operation[8] = self.thread as u8;
        operation[15] = 0xbe;
        PreparedCandidate::new(Candidate {
            id: attempt(self.opened.info, operation),
            codec: CANDIDATE_VERSION,
            predicates: vec![Predicate {
                address: addr(b"head"),
                expected: if first {
                    ExpectedValue::Absent
                } else {
                    ExpectedValue::Exact(Secret::new(previous))
                },
            }],
            mutations: vec![
                Mutation::Put {
                    address: addr(b"head"),
                    value: Secret::new(self.head.clone()),
                },
                Mutation::Put {
                    address: addr(&record_key(self.n % RECORD_KEYS)),
                    value: Secret::new(self.record.clone()),
                },
            ],
            time: None,
            result: Secret::new(vec![0xa5; RESULT_BYTES]),
        })
        .map_err(|e| format!("candidate: {e:?}"))
    }
}

fn applied(decision: Decision) -> Result<(), String> {
    match decision {
        Decision::Applied(_) => Ok(()),
        other => Err(format!("commit answered {other:?} (applied expected)")),
    }
}

impl Scenario for Commit {
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String> {
        let candidate = self.candidate(false)?;
        let key = self.key()?;
        let (rt, backend) = (&self.rt, &self.opened.backend);
        let decision = rec.time(0, || rt.block_on(backend.commit(candidate, key)));
        applied(decision.map_err(|e| format!("measured commit: {e:?}"))?)
    }
}

/// Read the thread's head and one record: two addresses.
struct Read {
    opened: Arc<Opened>,
    rt: tokio::runtime::Runtime,
    request: Arc<ReadRequest>,
}

impl Read {
    fn new(opened: Arc<Opened>, thread: usize) -> Result<Self, String> {
        // The read thread's own namespace, given a head and record 1 by one untimed commit.
        drop(Commit::new(opened.clone(), thread + 128)?);
        let ns = namespace(thread + 128);
        let request = Arc::new(ReadRequest {
            dataset: opened.info.dataset,
            addresses: vec![
                Address {
                    namespace: ns,
                    key: b"head".to_vec(),
                },
                Address {
                    namespace: ns,
                    key: record_key(1),
                },
            ],
            time: None,
        });
        Ok(Self {
            opened,
            rt: runtime()?,
            request,
        })
    }
}

impl Scenario for Read {
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String> {
        let (rt, backend) = (&self.rt, &self.opened.backend);
        let request = Arc::clone(&self.request);
        match rec.time(0, || rt.block_on(backend.read(request))) {
            Ok(ReadResult::Values { .. }) => Ok(()),
            other => Err(format!("read answered {other:?}")),
        }
    }
}

/// The store's clock: the cheapest kind op, close to the crossing's own floor.
struct Clock {
    opened: Arc<Opened>,
    rt: tokio::runtime::Runtime,
}

impl Clock {
    fn new(opened: Arc<Opened>) -> Result<Self, String> {
        Ok(Self {
            opened,
            rt: runtime()?,
        })
    }
}

impl Scenario for Clock {
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String> {
        let (rt, backend) = (&self.rt, &self.opened.backend);
        let dataset = self.opened.info.dataset;
        rec.time(0, || rt.block_on(backend.clock(dataset)))
            .map(drop)
            .map_err(|e| format!("clock answered {e:?}"))
    }
}
