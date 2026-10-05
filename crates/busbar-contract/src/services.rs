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
/// at most once per completion handle. Every service is required, with no default body (spec
/// #38(a)): an implementor that does not serve one says so in its own body, never by inheriting.
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
    fn records_get(&self, caller: &Caller, kind: &str, key: &[u8], later: Later) -> Ran;

    /// `records.list`: `caller`'s records of `kind` under `prefix`, after `after`, in key order, at
    /// most `limit` (`0` = as many as one answer carries); one span per record, key and value.
    fn records_list(&self, caller: &Caller, list: RecordsList, later: Later) -> Ran;

    /// `records.claim`: put `key` of `kind` if absent, standing `ttl_ms` (never `0`). READY
    /// `CLAIM_WON` or `CLAIM_TAKEN`.
    fn records_claim(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        ttl_ms: u64,
        later: Later,
    ) -> Ran;

    /// `sign`: sign `data` under `caller`'s declared signing domain. Span `0`: key = the key id,
    /// value = the signature. Never pends.
    fn sign(&self, caller: &Caller, data: &[u8]) -> Stored;

    /// `trust.sight`: judge `hash`, the catalogue `counterparty` reports, against the kernel's trust
    /// state. READY with a `TRUST_*` verdict.
    fn trust_sight(&self, caller: &Caller, counterparty: &str, hash: &str, later: Later) -> Ran;

    /// `trust.due`: the counterparties of `caller` the kernel's tick marked for re-verification, one
    /// span each (key = the counterparty), drained. Never pends.
    fn trust_due(&self, caller: &Caller) -> Stored;

    /// `trust.verify`: verify `signatures` (a JSON array as the document wrote it; empty = none)
    /// over `payload` against the root key `caller`'s declared pin names for `counterparty`. READY
    /// with a `SIGNED_*` verdict; the bytes name a refused algorithm or critical member. Never pends.
    fn trust_verify(
        &self,
        caller: &Caller,
        counterparty: &str,
        payload: &[u8],
        signatures: &[u8],
    ) -> Stored;

    /// `entitlement.check`: whether the principal of `unit` (the unit the calling crossing
    /// serves, `None` for a crossing that serves none) is entitled to `target`,
    /// `"<scope_kind>:<name>"`. READY `ENTITLED` or `NOT_ENTITLED`. Never pends.
    fn entitlement_check(&self, caller: &Caller, unit: Option<u64>, target: &str) -> Stored;

    /// `random.fill`: `len` bytes from the kernel's CSPRNG, READY with exactly those bytes; `len`
    /// outside `1..=MAX_RANDOM_FILL` is REFUSED, an OS randomness failure FAILED. Never pends.
    fn random_fill(&self, len: u64) -> Stored;

    /// `records.secret`: the secret of the host-held credential `id` of `kind`, and whether it is
    /// live (`SECRET_LIVE`), in span `0`; an unknown id answers a fixed dummy secret, not live, in
    /// equal time. The loader has already checked that the caller declared `kind`. A host with no
    /// credential source refuses.
    fn records_secret(&self, kind: &str, id: &str, later: Later) -> Ran;

    /// `unit.nest`: run `ask` as a nested unit, a child of `unit` (the unit the calling crossing
    /// serves; `None` = it serves none, REFUSED): under its principal, its scope and its admission
    /// chain, depth-capped, on whatever serves the claim `ask` names. READY with the child's status
    /// as `value`, span `0`'s value its body and each span after it one head field. The kernel never
    /// learns what the child is.
    fn unit_nest(&self, caller: &Caller, unit: Option<u64>, ask: NestAsk, later: Later) -> Ran;

    /// `work.open`: open a durable work handle of `kind` (a record kind `caller` declared) for the
    /// principal of `unit`, with `record`. READY with the handle, span `0`'s key its reference.
    fn work_open(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        kind: &str,
        record: &[u8],
        later: Later,
    ) -> Ran;

    /// `work.find`: the handle `reference` names, within `caller` and the principal of `unit`.
    /// Every denial is READY `ABSENT` with nothing written; found, READY with the handle, span
    /// `0`'s key the state byte and its value the record.
    fn work_find(&self, caller: &Caller, unit: Option<u64>, reference: &[u8], later: Later) -> Ran;

    /// `work.settle`: settle `caller`'s live handle `handle` with its final `record`. READY `0`.
    fn work_settle(&self, caller: &Caller, handle: u64, record: &[u8], later: Later) -> Ran;

    /// `work.resume`: bind `caller`'s handle `handle` to `unit`, whose principal must be the one the
    /// handle recorded. READY `0`, span `0`'s key the state byte and its value the record.
    fn work_resume(&self, caller: &Caller, unit: Option<u64>, handle: u64, later: Later) -> Ran;

    /// `disk.append` (THE DESIGN, the host's bounded disk lane): append `bytes` to the
    /// file `dest` names, rotating it first when `dest` says it is due, OFF the caller's thread,
    /// and hand the [`DiskReport`] (as [`DiskReport::stored`]) to `later`. The loader has already
    /// mapped the caller's destination key to `dest`. A host with no disk lane refuses.
    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran;
}

/// A `unit.nest` request, as the host copied it out of the caller's `in`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestAsk {
    /// The claim's verb.
    pub verb: String,
    /// The claim's target.
    pub target: String,
    /// The body.
    pub body: Vec<u8>,
}

/// A DESTINATION the host bound for an opened instance (THE DESIGN, host service `disk.append`): the
/// file the operator's configuration gives a key the plugin's manifest declares, and the rotation
/// the host applies to it. The plugin names the key; nothing here comes from the plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskDest {
    /// The declared settings key.
    pub key: String,
    /// The path the operator configured under it.
    pub path: String,
    /// Rotate before an append that finds the file at least this many bytes long; `None` = never.
    pub rotate_at: Option<u64>,
    /// How many archives a rotation keeps (`<path>.1` .. `<path>.{keep}`).
    pub keep: u32,
}

/// How many archives the host keeps for a destination it rotates (`<path>.1` .. `<path>.9`): the
/// retention the disk lane applies, never a plugin's parameter.
pub const DISK_KEEP: u32 = 9;

/// The settings key beside a destination that states its rotation threshold, in MiB: the host's
/// own rotation grammar (the key `plugins.logs` rotates its files by, and the frozen 1.5.x
/// request-log file sink's). Unset: the destination is never rotated.
pub const DISK_ROTATE_KEY: &str = "rotate_mb";

/// What one `disk.append` did, as the disk lane reports it and the mechanism stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskReport {
    /// `0` = the bytes landed; else the failed step (`DISK_OPEN_FAILED` / `DISK_APPEND_FAILED`).
    pub step: u64,
    /// Whether the file was rotated (renamed to its first archive) before the append.
    pub rotated: bool,
    /// The rotation steps that failed (`DISK_RETENTION_FAILED` | ...).
    pub faults: u8,
    /// For a failed step: why, in the operating system's words.
    pub error: &'static str,
}

impl DiskReport {
    /// The report as the mechanism stores it under the call's handle: READY or FAILED, the step in
    /// `value`'s low byte, `rotated` and `faults` above it.
    #[must_use]
    pub fn stored(self) -> Stored {
        let value = self.step | (u64::from(self.rotated) << 8) | (u64::from(self.faults) << 16);
        Stored {
            outcome: if self.step == 0 {
                Outcome::Ready
            } else {
                Outcome::Failed
            },
            error: self.error,
            ..Stored::ready(value)
        }
    }

    /// The report a stored READY or FAILED `disk.append` holds ([`Self::stored`]'s inverse).
    #[must_use]
    pub fn of(stored: &Stored) -> Self {
        Self {
            step: stored.value & 0xff,
            rotated: (stored.value >> 8) & 1 == 1,
            faults: ((stored.value >> 16) & 0xff) as u8,
            error: stored.error,
        }
    }
}

/// THE HOST-HELD CREDENTIAL READ `records.secret` serves: the secret of credential `id` of `kind`
/// and whether it may authenticate now. An unknown id answers a fixed dummy secret, not live, at the
/// same cost (the kernel's credential lookup holds that rule; an implementation only delegates).
pub trait CredentialRead: Send + Sync {
    /// The secret and its liveness.
    fn read(&self, kind: &str, id: &str) -> (crate::redacted::Redacted<String>, bool);
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
/// keys after `after`, in key order, at most `limit`. An empty value is a tombstone: its key is
/// absent, and a queued tombstone hides the stored row under it.
#[must_use]
pub fn merge_list(
    stored: Vec<(Vec<u8>, Vec<u8>)>,
    queued: Vec<(Vec<u8>, Vec<u8>)>,
    after: Option<&[u8]>,
    limit: usize,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows: BTreeMap<Vec<u8>, Vec<u8>> = stored.into_iter().collect();
    rows.extend(queued);
    rows.into_iter()
        .filter(|(k, v)| !v.is_empty() && after.is_none_or(|a| k.as_slice() > a))
        .take(limit)
        .collect()
}

#[cfg(test)]
#[path = "tests/services_tests.rs"]
mod tests;
