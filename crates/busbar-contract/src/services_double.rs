// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHARED HOST-SERVICES TEST DOUBLE (busbar #476 follow-up): one [`HostServices`] double the
//! fleet's tests write against, kept in step with the trait HERE, so a service the host adds is one
//! edit in this file rather than one in every plugin repo's hand-written double.
//!
//! A test implements [`ServicesDouble`] for its own type, overriding only the services it serves;
//! every other service answers as a host that does not serve it: REFUSED with
//! [`UNSERVED`](super::UNSERVED), at once (its [`Later`] dropped, never called), and the clock reads
//! zero. The blanket impl makes every [`ServicesDouble`] a [`HostServices`], so it goes wherever the
//! host's services go (`Arc::new(MyDouble)` into the loader's dispatcher). [`Unserved`] is the
//! double that overrides nothing.
//!
//! ```ignore
//! use busbar_contract::services::{double::ServicesDouble, Reading};
//! struct Clock;
//! impl ServicesDouble for Clock {
//!     fn now(&self) -> Reading { Reading { wall_ns: 7, mono_ns: 7 } }
//! }
//! ```
//!
//! Name the trait by its path in the `impl` (as above) rather than importing it beside
//! [`HostServices`]: with both in scope a direct `double.now()` call names two traits' methods.
//!
//! NOT IN A RELEASE BUILD. This module is compiled only for this crate's own tests or under the
//! dev-only `services-double` feature, which a plugin enables on its `[dev-dependencies]` edge alone
//! (`tests/test_seal_is_dev_only.rs` refuses any other edge; `tests/feature_invariance.rs` holds the
//! feature to this one item). It holds no state of its own.
//!
//! ADDING A SERVICE: add it to [`ServicesDouble`] with a body that answers as an unserved host
//! does, forward it in the blanket impl below, and add its row to the coverage test
//! (`tests/services_double_tests.rs`), which reads the trait's own source and fails on a service
//! it does not call.

use super::{
    Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Stored,
    UNSERVED,
};

/// The answer of a service this double does not serve, for a service that may pend.
fn refused() -> Ran {
    Ran::Now(Stored::refused(UNSERVED))
}

/// THE HOST SERVICES, WITH A REFUSING DEFAULT FOR EACH: implement it for a test's own type and
/// override only what the test serves. Each method is the [`HostServices`] method of the same
/// name; the blanket impl forwards one to the other.
pub trait ServicesDouble: Send + Sync {
    /// `clock.now`. Unserved: the zero reading.
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 0,
            mono_ns: 0,
        }
    }

    /// `dest.judge`. Unserved: REFUSED.
    fn dest_judge(&self, _dest: &str, _class: u32, _flags: u32, _later: Option<Later>) -> Ran {
        refused()
    }

    /// `records.get`. Unserved: REFUSED.
    fn records_get(&self, _caller: &Caller, _kind: &str, _key: &[u8], _later: Later) -> Ran {
        refused()
    }

    /// `records.list`. Unserved: REFUSED.
    fn records_list(&self, _caller: &Caller, _list: RecordsList, _later: Later) -> Ran {
        refused()
    }

    /// `records.claim`. Unserved: REFUSED.
    fn records_claim(
        &self,
        _caller: &Caller,
        _kind: &str,
        _key: &[u8],
        _ttl_ms: u64,
        _later: Later,
    ) -> Ran {
        refused()
    }

    /// `sign`. Unserved: REFUSED.
    fn sign(&self, _caller: &Caller, _data: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }

    /// `trust.sight`. Unserved: REFUSED.
    fn trust_sight(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _hash: &str,
        _later: Later,
    ) -> Ran {
        refused()
    }

    /// `trust.due`. Unserved: REFUSED.
    fn trust_due(&self, _caller: &Caller) -> Stored {
        Stored::refused(UNSERVED)
    }

    /// `trust.verify`. Unserved: REFUSED.
    fn trust_verify(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _payload: &[u8],
        _signatures: &[u8],
    ) -> Stored {
        Stored::refused(UNSERVED)
    }

    /// `entitlement.check`. Unserved: REFUSED.
    fn entitlement_check(&self, _caller: &Caller, _unit: Option<u64>, _target: &str) -> Stored {
        Stored::refused(UNSERVED)
    }

    /// `random.fill`. Unserved: REFUSED.
    fn random_fill(&self, _len: u64) -> Stored {
        Stored::refused(UNSERVED)
    }

    /// `records.secret`. Unserved (a host with no credential source): REFUSED.
    fn records_secret(&self, _kind: &str, _id: &str, _later: Later) -> Ran {
        refused()
    }

    /// `unit.nest`. Unserved: REFUSED.
    fn unit_nest(&self, _caller: &Caller, _unit: Option<u64>, _ask: NestAsk, _later: Later) -> Ran {
        refused()
    }

    /// `work.open`. Unserved: REFUSED.
    fn work_open(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _kind: &str,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        refused()
    }

    /// `work.find`. Unserved: REFUSED.
    fn work_find(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _reference: &[u8],
        _later: Later,
    ) -> Ran {
        refused()
    }

    /// `work.settle`. Unserved: REFUSED.
    fn work_settle(&self, _caller: &Caller, _handle: u64, _record: &[u8], _later: Later) -> Ran {
        refused()
    }

    /// `work.resume`. Unserved: REFUSED.
    fn work_resume(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _later: Later,
    ) -> Ran {
        refused()
    }

    /// `disk.append`. Unserved (a host with no disk lane): REFUSED.
    fn disk_append(&self, _dest: &DiskDest, _bytes: Vec<u8>, _later: Later) -> Ran {
        refused()
    }

    /// `verify.lookup`. Unserved: REFUSED.
    fn verify_lookup(&self, _caller: &Caller, _key: &[u8], _later: Later) -> Ran {
        refused()
    }

    /// `verify.store`. Unserved: REFUSED.
    fn verify_store(&self, _caller: &Caller, _key: &[u8], _entry: &[u8], _ttl_ms: u64) -> Stored {
        Stored::refused(UNSERVED)
    }

    /// `content.scan`. Unserved: REFUSED.
    fn content_scan(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _content: &[u8],
        _later: Later,
    ) -> Ran {
        refused()
    }

    /// `hook.call`. Unserved: REFUSED.
    fn hook_call(&self, _caller: &Caller, _unit: Option<u64>, _ask: HookAsk, _later: Later) -> Ran {
        refused()
    }
}

/// The double that serves nothing: every service answers as an unserved host's.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unserved;

impl ServicesDouble for Unserved {}

impl<T: ServicesDouble> HostServices for T {
    fn now(&self) -> Reading {
        ServicesDouble::now(self)
    }

    fn dest_judge(&self, dest: &str, class: u32, flags: u32, later: Option<Later>) -> Ran {
        ServicesDouble::dest_judge(self, dest, class, flags, later)
    }

    fn records_get(&self, caller: &Caller, kind: &str, key: &[u8], later: Later) -> Ran {
        ServicesDouble::records_get(self, caller, kind, key, later)
    }

    fn records_list(&self, caller: &Caller, list: RecordsList, later: Later) -> Ran {
        ServicesDouble::records_list(self, caller, list, later)
    }

    fn records_claim(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        ttl_ms: u64,
        later: Later,
    ) -> Ran {
        ServicesDouble::records_claim(self, caller, kind, key, ttl_ms, later)
    }

    fn sign(&self, caller: &Caller, data: &[u8]) -> Stored {
        ServicesDouble::sign(self, caller, data)
    }

    fn trust_sight(&self, caller: &Caller, counterparty: &str, hash: &str, later: Later) -> Ran {
        ServicesDouble::trust_sight(self, caller, counterparty, hash, later)
    }

    fn trust_due(&self, caller: &Caller) -> Stored {
        ServicesDouble::trust_due(self, caller)
    }

    fn trust_verify(
        &self,
        caller: &Caller,
        counterparty: &str,
        payload: &[u8],
        signatures: &[u8],
    ) -> Stored {
        ServicesDouble::trust_verify(self, caller, counterparty, payload, signatures)
    }

    fn entitlement_check(&self, caller: &Caller, unit: Option<u64>, target: &str) -> Stored {
        ServicesDouble::entitlement_check(self, caller, unit, target)
    }

    fn random_fill(&self, len: u64) -> Stored {
        ServicesDouble::random_fill(self, len)
    }

    fn records_secret(&self, kind: &str, id: &str, later: Later) -> Ran {
        ServicesDouble::records_secret(self, kind, id, later)
    }

    fn unit_nest(&self, caller: &Caller, unit: Option<u64>, ask: NestAsk, later: Later) -> Ran {
        ServicesDouble::unit_nest(self, caller, unit, ask, later)
    }

    fn work_open(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        kind: &str,
        record: &[u8],
        later: Later,
    ) -> Ran {
        ServicesDouble::work_open(self, caller, unit, kind, record, later)
    }

    fn work_find(&self, caller: &Caller, unit: Option<u64>, reference: &[u8], later: Later) -> Ran {
        ServicesDouble::work_find(self, caller, unit, reference, later)
    }

    fn work_settle(&self, caller: &Caller, handle: u64, record: &[u8], later: Later) -> Ran {
        ServicesDouble::work_settle(self, caller, handle, record, later)
    }

    fn work_resume(&self, caller: &Caller, unit: Option<u64>, handle: u64, later: Later) -> Ran {
        ServicesDouble::work_resume(self, caller, unit, handle, later)
    }

    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran {
        ServicesDouble::disk_append(self, dest, bytes, later)
    }

    fn verify_lookup(&self, caller: &Caller, key: &[u8], later: Later) -> Ran {
        ServicesDouble::verify_lookup(self, caller, key, later)
    }

    fn verify_store(&self, caller: &Caller, key: &[u8], entry: &[u8], ttl_ms: u64) -> Stored {
        ServicesDouble::verify_store(self, caller, key, entry, ttl_ms)
    }

    fn content_scan(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        content: &[u8],
        later: Later,
    ) -> Ran {
        ServicesDouble::content_scan(self, caller, unit, content, later)
    }

    fn hook_call(&self, caller: &Caller, unit: Option<u64>, ask: HookAsk, later: Later) -> Ran {
        ServicesDouble::hook_call(self, caller, unit, ask, later)
    }
}

#[cfg(test)]
#[path = "tests/services_double_tests.rs"]
mod tests;
