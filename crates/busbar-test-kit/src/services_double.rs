// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST-SERVICES TEST DOUBLE: one [`HostServices`] double the fleet's tests write against, so
//! a service the host adds is one edit here rather than one in every plugin repo's double.
//!
//! A test implements [`ServicesDouble`] for its own type, overriding only the services it serves,
//! and hands the host `Arc::new(Double(mine))`: every other service answers as a host that does not
//! serve it, REFUSED with [`UNSERVED`] at once (its [`Later`] dropped, never called), and the clock
//! reads zero. [`Double`] derefs to the wrapped value, so a test still reads its own counters
//! through the `Arc`. [`Unserved`] is the double that overrides nothing.
//!
//! ```ignore
//! use busbar_contract::services::Reading;
//! use busbar_test_kit::services_double::{Double, ServicesDouble};
//! struct Clock;
//! impl ServicesDouble for Clock {
//!     fn now(&self) -> Reading { Reading { wall_ns: 7, mono_ns: 7 } }
//! }
//! let host: std::sync::Arc<dyn busbar_contract::services::HostServices> =
//!     std::sync::Arc::new(Double(Clock));
//! ```

use busbar_contract::services::{
    Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Snapshot,
    Stored, TrustKeyRef, UNSERVED,
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

    /// `trust.sight` with `TRUST_UNREACHABLE`. Unserved: REFUSED.
    fn trust_unreached(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        Stored::refused(UNSERVED)
    }

    /// `trust.sight_item`. Unserved: REFUSED.
    fn trust_sight_item(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: &str,
        _digest: &str,
    ) -> Stored {
        Stored::refused(UNSERVED)
    }

    /// `trust.decide`. Unserved: REFUSED.
    fn trust_decide(
        &self,
        _caller: &Caller,
        _key: TrustKeyRef<'_>,
        _expected: Option<&str>,
        _approve: bool,
    ) -> Stored {
        Stored::refused(UNSERVED)
    }

    /// `trust.state`. Unserved: REFUSED.
    fn trust_state(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        Stored::refused(UNSERVED)
    }

    /// `trust.serves`. Unserved: REFUSED.
    fn trust_serves(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: Option<&str>,
        _digest: Option<&str>,
    ) -> Stored {
        Stored::refused(UNSERVED)
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

    /// `session.emit`. Unserved (a host that holds no carrier session): REFUSED.
    fn session_emit(&self, _caller: &Caller, _session: u64, _bytes: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }

    /// `ticket.mint`. Unserved (a host that mints no tickets): REFUSED.
    fn ticket_mint(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _ttl_secs: u64,
        _record: &[u8],
    ) -> Stored {
        Stored::refused(UNSERVED)
    }

    /// `ticket.take`. Unserved (a host that mints no tickets): REFUSED.
    fn ticket_take(&self, _caller: &Caller, _unit: Option<u64>) -> Stored {
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
    fn work_settle(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
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

    /// `snapshot.read`. Unserved (a host with no snapshot for this caller): REFUSED.
    fn snapshot_read(&self, _caller: &Caller, _scope: u32) -> Snapshot {
        Snapshot::Refused(UNSERVED)
    }
}

/// The double that serves nothing: every service answers as an unserved host's.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unserved;

impl ServicesDouble for Unserved {}

/// A [`ServicesDouble`] as the host's services: `Arc::new(Double(mine))` goes wherever the
/// host's services go.
#[derive(Debug, Clone, Copy, Default)]
pub struct Double<T>(pub T);

impl<T> std::ops::Deref for Double<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ServicesDouble> HostServices for Double<T> {
    fn now(&self) -> Reading {
        ServicesDouble::now(&self.0)
    }

    fn dest_judge(&self, dest: &str, class: u32, flags: u32, later: Option<Later>) -> Ran {
        ServicesDouble::dest_judge(&self.0, dest, class, flags, later)
    }

    fn records_get(&self, caller: &Caller, kind: &str, key: &[u8], later: Later) -> Ran {
        ServicesDouble::records_get(&self.0, caller, kind, key, later)
    }

    fn records_list(&self, caller: &Caller, list: RecordsList, later: Later) -> Ran {
        ServicesDouble::records_list(&self.0, caller, list, later)
    }

    fn records_claim(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        ttl_ms: u64,
        later: Later,
    ) -> Ran {
        ServicesDouble::records_claim(&self.0, caller, kind, key, ttl_ms, later)
    }

    fn sign(&self, caller: &Caller, data: &[u8]) -> Stored {
        ServicesDouble::sign(&self.0, caller, data)
    }

    fn trust_sight(&self, caller: &Caller, counterparty: &str, hash: &str, later: Later) -> Ran {
        ServicesDouble::trust_sight(&self.0, caller, counterparty, hash, later)
    }

    fn trust_unreached(&self, caller: &Caller, counterparty: &str) -> Stored {
        ServicesDouble::trust_unreached(&self.0, caller, counterparty)
    }

    fn trust_sight_item(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: &str,
        digest: &str,
    ) -> Stored {
        ServicesDouble::trust_sight_item(&self.0, caller, counterparty, item, digest)
    }

    fn trust_decide(
        &self,
        caller: &Caller,
        key: TrustKeyRef<'_>,
        expected: Option<&str>,
        approve: bool,
    ) -> Stored {
        ServicesDouble::trust_decide(&self.0, caller, key, expected, approve)
    }

    fn trust_state(&self, caller: &Caller, counterparty: &str) -> Stored {
        ServicesDouble::trust_state(&self.0, caller, counterparty)
    }

    fn trust_serves(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: Option<&str>,
        digest: Option<&str>,
    ) -> Stored {
        ServicesDouble::trust_serves(&self.0, caller, counterparty, item, digest)
    }

    fn session_emit(&self, caller: &Caller, session: u64, bytes: &[u8]) -> Stored {
        ServicesDouble::session_emit(&self.0, caller, session, bytes)
    }

    fn ticket_mint(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        ttl_secs: u64,
        record: &[u8],
    ) -> Stored {
        ServicesDouble::ticket_mint(self, caller, unit, ttl_secs, record)
    }

    fn ticket_take(&self, caller: &Caller, unit: Option<u64>) -> Stored {
        ServicesDouble::ticket_take(self, caller, unit)
    }

    fn trust_due(&self, caller: &Caller) -> Stored {
        ServicesDouble::trust_due(&self.0, caller)
    }

    fn trust_verify(
        &self,
        caller: &Caller,
        counterparty: &str,
        payload: &[u8],
        signatures: &[u8],
    ) -> Stored {
        ServicesDouble::trust_verify(&self.0, caller, counterparty, payload, signatures)
    }

    fn entitlement_check(&self, caller: &Caller, unit: Option<u64>, target: &str) -> Stored {
        ServicesDouble::entitlement_check(&self.0, caller, unit, target)
    }

    fn random_fill(&self, len: u64) -> Stored {
        ServicesDouble::random_fill(&self.0, len)
    }

    fn records_secret(&self, kind: &str, id: &str, later: Later) -> Ran {
        ServicesDouble::records_secret(&self.0, kind, id, later)
    }

    fn unit_nest(&self, caller: &Caller, unit: Option<u64>, ask: NestAsk, later: Later) -> Ran {
        ServicesDouble::unit_nest(&self.0, caller, unit, ask, later)
    }

    fn work_open(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        kind: &str,
        record: &[u8],
        later: Later,
    ) -> Ran {
        ServicesDouble::work_open(&self.0, caller, unit, kind, record, later)
    }

    fn work_find(&self, caller: &Caller, unit: Option<u64>, reference: &[u8], later: Later) -> Ran {
        ServicesDouble::work_find(&self.0, caller, unit, reference, later)
    }

    fn work_settle(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        handle: u64,
        record: &[u8],
        later: Later,
    ) -> Ran {
        ServicesDouble::work_settle(&self.0, caller, unit, handle, record, later)
    }

    fn work_resume(&self, caller: &Caller, unit: Option<u64>, handle: u64, later: Later) -> Ran {
        ServicesDouble::work_resume(&self.0, caller, unit, handle, later)
    }

    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran {
        ServicesDouble::disk_append(&self.0, dest, bytes, later)
    }

    fn verify_lookup(&self, caller: &Caller, key: &[u8], later: Later) -> Ran {
        ServicesDouble::verify_lookup(&self.0, caller, key, later)
    }

    fn verify_store(&self, caller: &Caller, key: &[u8], entry: &[u8], ttl_ms: u64) -> Stored {
        ServicesDouble::verify_store(&self.0, caller, key, entry, ttl_ms)
    }

    fn content_scan(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        content: &[u8],
        later: Later,
    ) -> Ran {
        ServicesDouble::content_scan(&self.0, caller, unit, content, later)
    }

    fn hook_call(&self, caller: &Caller, unit: Option<u64>, ask: HookAsk, later: Later) -> Ran {
        ServicesDouble::hook_call(&self.0, caller, unit, ask, later)
    }

    fn snapshot_read(&self, caller: &Caller, scope: u32) -> Snapshot {
        ServicesDouble::snapshot_read(&self.0, caller, scope)
    }
}

#[cfg(all(test, loader_self_tests))]
#[path = "tests/services_double_tests.rs"]
mod tests;
