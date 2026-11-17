// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The bench's host services: a fake clock and a fast deterministic `random.fill`; every other
//! service answers "unimplemented" at once (no records, trust, work, disk or hook backends), so a
//! plugin that needs one on its hot path shows it as a refusal rather than as the cost of a real
//! backend. Calls are counted, so a report can say how often a hot op reaches the host.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece, PieceKind,
};

use busbar_contract::abi::sdk::plane::conditional::ConditionalCandidate;
use busbar_contract::services::{
    Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Stored,
    TrustKeyRef, UNSERVED,
};

/// 2023-11-14T22:13:20Z: the fake clock's wall origin, advanced by the monotonic clock.
const WALL_ORIGIN_NS: u64 = 1_700_000_000_000_000_000;

#[derive(Debug)]
pub struct BenchHost {
    origin: Instant,
    seed: AtomicU64,
    pub calls: AtomicU64,
    pub refused: AtomicU64,
}

impl Default for BenchHost {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
            seed: AtomicU64::new(0x9e37_79b9_7f4a_7c15),
            calls: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        }
    }
}

impl BenchHost {
    fn unserved(&self) -> Stored {
        if crate::report::verbose() {
            eprintln!("[host] unserved service");
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.refused.fetch_add(1, Ordering::Relaxed);
        Stored::refused(UNSERVED)
    }

    fn later(&self) -> Ran {
        Ran::Now(self.unserved())
    }
}

/// splitmix64: fast, deterministic, good enough for ids a bench never trusts.
fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

impl HostServices for BenchHost {
    fn now(&self) -> Reading {
        if crate::report::verbose() {
            eprintln!("[host] clock.now");
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mono = self.origin.elapsed().as_nanos() as u64;
        Reading {
            wall_ns: WALL_ORIGIN_NS + mono,
            mono_ns: mono,
        }
    }

    fn random_fill(&self, len: u64) -> Stored {
        if crate::report::verbose() {
            eprintln!("[host] random.fill {len}");
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mut bytes = Vec::with_capacity(len as usize);
        while (bytes.len() as u64) < len {
            let z = mix(self
                .seed
                .fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed));
            let take = ((len as usize) - bytes.len()).min(8);
            bytes.extend_from_slice(&z.to_le_bytes()[..take]);
        }
        let mut s = Stored::ready(0);
        s.bytes = bytes;
        s
    }

    fn conditional_record_transaction(
        &self,
        _: &Caller,
        _: Option<u64>,
        _: ConditionalCandidate,
        _: Box<dyn FnOnce(busbar_contract::abi::sdk::plane::conditional::ConditionalResult) + Send>,
    ) -> Result<(), &'static str> {
        self.unserved();
        Err(UNSERVED)
    }

    fn dest_judge(&self, _: &str, _: u32, _: u32, _: Option<Later>) -> Ran {
        self.later()
    }
    fn records_get(&self, _: &Caller, _: &str, _: &[u8], _: Later) -> Ran {
        self.later()
    }
    fn records_list(&self, _: &Caller, _: RecordsList, _: Later) -> Ran {
        self.later()
    }
    fn records_claim(&self, _: &Caller, _: &str, _: &[u8], _: u64, _: Later) -> Ran {
        self.later()
    }
    fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
        self.unserved()
    }
    fn trust_sight(&self, _: &Caller, _: &str, _: &str, _: Later) -> Ran {
        self.later()
    }
    fn trust_unreached(&self, _: &Caller, _: &str) -> Stored {
        self.unserved()
    }
    fn trust_sight_item(&self, _: &Caller, _: &str, _: &str, _: &str, _: Later) -> Ran {
        self.later()
    }
    fn trust_decide(
        &self,
        _: &Caller,
        _: busbar_contract::abi::mechanism::ticket::Ticket,
        _: TrustKeyRef<'_>,
        _: Option<&str>,
        _: bool,
        _: Later,
    ) -> Ran {
        self.later()
    }
    fn trust_state(&self, _: &Caller, _: &str) -> Stored {
        self.unserved()
    }
    fn trust_serves(&self, _: &Caller, _: &str, _: Option<&str>, _: Option<&str>) -> Stored {
        self.unserved()
    }
    fn trust_due(&self, _: &Caller) -> Stored {
        self.unserved()
    }
    fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
        self.unserved()
    }
    fn session_emit(&self, _: &Caller, _: u64, _: &[u8]) -> Stored {
        self.unserved()
    }
    fn ticket_mint(&self, _: &Caller, _: Option<u64>, _: u64, _: &[u8], _: Later) -> Ran {
        self.later()
    }
    fn ticket_take(&self, _: &Caller, _: Option<u64>) -> Stored {
        self.unserved()
    }
    fn records_secret(&self, _: &str, _: &str, _: Later) -> Ran {
        self.later()
    }
    fn unit_nest(&self, _: &Caller, _: Option<u64>, _: NestAsk, _: Later) -> Ran {
        self.later()
    }
    fn work_open(&self, _: &Caller, _: Option<u64>, _: &str, _: &[u8], _: Later) -> Ran {
        self.later()
    }
    fn work_find(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Later) -> Ran {
        self.later()
    }
    fn work_settle(&self, _: &Caller, _: Option<u64>, _: u64, _: &[u8], _: Later) -> Ran {
        self.later()
    }
    fn work_resume(&self, _: &Caller, _: Option<u64>, _: u64, _: Later) -> Ran {
        self.later()
    }
    fn disk_append(&self, _: &DiskDest, _: Vec<u8>, _: Later) -> Ran {
        self.later()
    }
    fn verify_lookup(&self, _: &Caller, _: &[u8], _: Later) -> Ran {
        self.later()
    }
    fn verify_store(&self, _: &Caller, _: &[u8], _: &[u8], _: u64) -> Stored {
        self.unserved()
    }
    fn content_scan(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Later) -> Ran {
        self.later()
    }
    fn hook_call(&self, _: &Caller, _: Option<u64>, _: HookAsk, _: Later) -> Ran {
        self.later()
    }
    fn snapshot_read(&self, _: &Caller, _: u32, _: Later) -> Ran {
        self.later()
    }
}

/// THE FAR END a kind's declared need reaches, in memory: every need declared on it is accepted
/// (any target), it carries framed `http`, and every request opened on it is taken whole (head,
/// fields and body, handed over by the host as one `open`), discarded, and answered `200` with an
/// empty body (an OTLP collector's empty `ExportTraceServiceResponse`). No socket, no thread, no
/// per-request allocation of its own once its connection book has grown to the thread count: a
/// connection is a slot in one locked book, freed on `close`. Opens are counted globally and per
/// calling thread ([`SinkConns::opened_here`]), so a workload can prove each measured call reached
/// the far end exactly once.
#[derive(Debug, Default)]
pub struct SinkConns {
    declared: std::sync::Mutex<Vec<(InstanceId, NeedId)>>,
    /// Per slot: its generation and the reads it answered (`u8::MAX` = free).
    book: std::sync::Mutex<Book>,
    pub opened: AtomicU64,
    pub bytes: AtomicU64,
}

const FREE: u8 = u8::MAX;

/// The connection book: per slot its generation and reads answered, and the free slots.
type Book = (Vec<(u32, u8)>, Vec<usize>);

thread_local! {
    static OPENED_HERE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

impl SinkConns {
    /// How many requests this thread opened on any `SinkConns`.
    pub fn opened_here() -> u64 {
        OPENED_HERE.with(std::cell::Cell::get)
    }

    fn book(&self) -> std::sync::MutexGuard<'_, Book> {
        self.book
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn slot(conn: ConnId) -> (usize, u32) {
        (
            ((conn.0 & 0xffff_ffff) as usize).wrapping_sub(1),
            (conn.0 >> 32) as u32,
        )
    }
}

impl DeclaredConns for SinkConns {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        _: &ReadNeed,
        target: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        if crate::report::verbose() {
            eprintln!("[conns] declare need {} -> {target:?}", need.0);
        }
        self.declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((owner, need));
        Ok(())
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&(owner, need))
            .then_some(Ok(()))
    }
    fn framed(&self, owner: InstanceId, need: NeedId) -> bool {
        DeclaredConns::declared(self, owner, need).is_some()
    }
    fn serves_scheme(&self, transport: &str) -> bool {
        transport == "http"
    }
    fn forget(&self, owner: InstanceId) {
        self.declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(o, _)| *o != owner);
    }
}

impl Conns for SinkConns {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        if DeclaredConns::declared(self, caller, need).is_none() {
            return Err(ConnError::UndeclaredNeed);
        }
        if crate::report::verbose() {
            eprintln!(
                "[conns] open {} {} {} fields={} body={}B",
                String::from_utf8_lossy(desc.method),
                desc.target,
                String::from_utf8_lossy(desc.head_target),
                desc.fields.len(),
                desc.body.len()
            );
        }
        self.opened.fetch_add(1, Ordering::Relaxed);
        self.bytes
            .fetch_add(desc.body.len() as u64, Ordering::Relaxed);
        OPENED_HERE.with(|n| n.set(n.get() + 1));
        let mut book = self.book();
        let (index, generation) = match book.1.pop() {
            Some(i) => {
                book.0[i].1 = 0;
                (i, book.0[i].0)
            }
            None => {
                book.0.push((0, 0));
                (book.0.len() - 1, 0)
            }
        };
        Ok(ConnId((u64::from(generation) << 32) | (index as u64 + 1)))
    }
    fn open_with_security(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        _require_secure: bool,
    ) -> Result<ConnId, ConnError> {
        // A modeled secured far end: a credential that requires connection security is carried.
        self.open(caller, need, desc)
    }
    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn read(&self, _: InstanceId, conn: ConnId, _: u64, _: &mut [u8]) -> Result<Piece, ConnError> {
        let (index, generation) = Self::slot(conn);
        let n = {
            let mut book = self.book();
            let Some(entry) = book
                .0
                .get_mut(index)
                .filter(|e| e.0 == generation && e.1 != FREE)
            else {
                return Err(ConnError::Closed);
            };
            entry.1 += 1;
            entry.1
        };
        let kind = match n {
            1 => PieceKind::Fields,
            2 => PieceKind::Completion,
            _ => return Err(ConnError::Closed),
        };
        let head = n == 1;
        Ok(Piece {
            kind,
            stream: busbar_contract::ids::StreamId(0),
            len: 0,
            end: true,
            status: head.then_some(busbar_contract::transport::wire::WireStatusClass::Success),
            status_code: head.then_some(200),
            status_namespace: None,
            retry_after_secs: None,
            fault: None,
            reason: None,
            declared_len: None,
        })
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Ok(0)
    }
    fn facts(
        &self,
        _: InstanceId,
        _: ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, ConnError> {
        Ok(busbar_contract::transport::ConnFacts::default())
    }
    fn close(&self, _: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        let (index, generation) = Self::slot(conn);
        let mut book = self.book();
        match book.0.get_mut(index) {
            Some(entry) if entry.0 == generation && entry.1 != FREE => {
                *entry = (generation.wrapping_add(1), FREE);
                book.1.push(index);
                Ok(())
            }
            _ => Err(ConnError::Closed),
        }
    }
}
