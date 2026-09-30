// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST SERVICES, AS THE HOST'S TWO HALVES SHARE THEM (`BUSBAR-1.6.0.md` THE DESIGN, host
//! services): the [`HostServices`] trait the kernel implements and the plugin loader dispatches
//! into, and the result types that cross between them. The kernel names this, the loader names
//! this, and neither names the other. The ABI a plugin sees is `abi::host::service`; nothing here
//! crosses the plugin boundary.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::abi::host::service::ItemSpan;
use crate::abi::mechanism::call::Outcome;
use crate::abi::mechanism::KindCode;

/// Who called a service: the opened instance, by the label the host configured for it, the plugin
/// it is an instance of, and its kind. The loader states it at bind. The kernel keys every
/// per-instance fact it holds by `instance`, never by `plugin`: two instances of one plugin share a
/// Statement name and never a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The host's label for this opened instance, unique per instance.
    pub instance: Arc<str>,
    /// The plugin's Statement name.
    pub plugin: Arc<str>,
    /// Its kind.
    pub kind: KindCode,
}

/// The error text of a service this host does not serve.
pub const UNSERVED: &str = "unimplemented";

/// A reading of the kernel's one clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    /// Nanoseconds since the Unix epoch.
    pub wall_ns: u64,
    /// Nanoseconds since the clock's fixed origin.
    pub mono_ns: u64,
}

/// Where a pended service's result goes: called once, from any thread. The mechanism stores the
/// result under the call's handle and wakes its ticket.
pub type Later = Box<dyn FnOnce(Stored) + Send>;

/// THE HOST SERVICES, as the kernel implements them. The dispatcher holds one for every instance it
/// adopts; each slot validates the caller's `in`, applies the mechanism's rules, and calls in here
/// at most once per completion handle.
pub trait HostServices: Send + Sync {
    /// `clock.now`: the kernel's one clock. Never pends.
    fn now(&self) -> Reading;

    /// `dest.judge`: judge `dest` against egress class `class`'s rules; `resolve` = the caller set
    /// `DEST_RESOLVE`. Answers [`Ran::Now`] with a `DEST_*` verdict (or REFUSED for an unknown
    /// class), or hands `later` on and answers [`Ran::Later`]. `later` is `None` only for a call
    /// that may not pend, which never reaches here for this service.
    fn dest_judge(&self, dest: &str, class: u32, resolve: bool, later: Option<Later>) -> Ran;

    /// `records.get`: `caller`'s record of `kind` under `key`, its own queued writes first.
    /// READY `FOUND` with span `0`'s value the record, or READY `ABSENT`.
    fn records_get(&self, caller: &Caller, kind: &str, key: &[u8], later: Later) -> Ran {
        let _ = (caller, kind, key, later);
        Ran::Now(Stored::refused(UNSERVED))
    }

    /// `records.list`: `caller`'s records of `kind` under `prefix`, after `after`, in key order, at
    /// most `limit` (`0` = as many as one answer carries); one span per record, key and value.
    fn records_list(&self, caller: &Caller, list: RecordsList, later: Later) -> Ran {
        let _ = (caller, list, later);
        Ran::Now(Stored::refused(UNSERVED))
    }

    /// `records.claim`: put `key` of `kind` if absent, standing `ttl_ms` (never `0`). READY
    /// `CLAIM_WON` or `CLAIM_TAKEN`.
    fn records_claim(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        ttl_ms: u64,
        later: Later,
    ) -> Ran {
        let _ = (caller, kind, key, ttl_ms, later);
        Ran::Now(Stored::refused(UNSERVED))
    }

    /// `sign`: sign `data` under `caller`'s declared signing domain. Span `0`: key = the key id,
    /// value = the signature. Never pends.
    fn sign(&self, caller: &Caller, data: &[u8]) -> Stored {
        let _ = (caller, data);
        Stored::refused(UNSERVED)
    }

    /// `trust.sight`: judge `hash`, the catalogue `counterparty` reports, against the kernel's trust
    /// state. READY with a `TRUST_*` verdict.
    fn trust_sight(&self, caller: &Caller, counterparty: &str, hash: &str, later: Later) -> Ran {
        let _ = (caller, counterparty, hash, later);
        Ran::Now(Stored::refused(UNSERVED))
    }

    /// `trust.due`: the counterparties of `caller` the kernel's tick marked for re-verification, one
    /// span each (key = the counterparty), drained. Never pends.
    fn trust_due(&self, caller: &Caller) -> Stored {
        let _ = caller;
        Stored::refused(UNSERVED)
    }
}

/// A `records.list` request, as the host copied it out of the caller's `in`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordsList {
    /// The record kind.
    pub kind: String,
    /// The key prefix; empty = every key.
    pub prefix: Vec<u8>,
    /// List after this key; `None` = from the first.
    pub after: Option<Vec<u8>>,
    /// The most records; `0` = as many as one answer carries.
    pub limit: u32,
}

/// One service result, as the host stores it under its handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// The outcome.
    pub outcome: Outcome,
    /// The scalar answer.
    pub value: u64,
    /// The bytes.
    pub bytes: Vec<u8>,
    /// The spans over them.
    pub spans: Vec<ItemSpan>,
    /// The reason, for FAILED/REFUSED.
    pub error: &'static str,
}

impl Stored {
    /// READY with `value` and no buffer.
    #[must_use]
    pub fn ready(value: u64) -> Self {
        Self {
            outcome: Outcome::Ready,
            value,
            bytes: Vec::new(),
            spans: Vec::new(),
            error: "",
        }
    }

    /// REFUSED for `why`.
    #[must_use]
    pub fn refused(why: &'static str) -> Self {
        Self {
            outcome: Outcome::Refused,
            error: why,
            ..Self::ready(0)
        }
    }
}

/// What a service body did.
#[derive(Debug)]
pub enum Ran {
    /// Finished.
    Now(Stored),
    /// Handed its [`Later`] on; the answer pends.
    Later,
}

/// THE LIST RULE: `stored` (the store's rows under the prefix) with `queued` laid over them, the
/// keys after `after`, in key order, at most `limit`.
#[must_use]
pub fn merge_list(
    stored: Vec<(Vec<u8>, Vec<u8>)>,
    queued: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    after: Option<&[u8]>,
    limit: usize,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows: BTreeMap<Vec<u8>, Vec<u8>> = stored.into_iter().collect();
    for (k, v) in queued {
        match v {
            Some(v) => {
                rows.insert(k, v);
            }
            None => {
                rows.remove(&k);
            }
        }
    }
    rows.into_iter()
        .filter(|(k, _)| after.is_none_or(|a| k.as_slice() > a))
        .take(limit)
        .collect()
}

#[cfg(test)]
#[path = "tests/services_tests.rs"]
mod tests;
