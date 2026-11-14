// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The bench's host services: a fake clock and a fast deterministic `random.fill`; every other
//! service answers "unimplemented" at once (no records, trust, work, disk or hook backends), so a
//! plugin that needs one on its hot path shows it as a refusal rather than as the cost of a real
//! backend. Calls are counted, so a report can say how often a hot op reaches the host.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

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
    fn entitlement_check(&self, _: &Caller, _: Option<u64>, _: &str) -> Stored {
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
