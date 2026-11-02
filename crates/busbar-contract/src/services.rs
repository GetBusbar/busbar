// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST SERVICES, AS THE HOST'S TWO HALVES SHARE THEM (`BUSBAR-1.6.0.md` THE DESIGN, host

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
pub type Later = Box<dyn FnOnce(Stored) + Send>;

/// One trust key a plane names (`trust.decide`): a counterparty of the calling instance, and
/// optionally one item there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustKeyRef<'a> {
    /// The counterparty.
    pub counterparty: &'a str,
    /// The item there; `None` = the counterparty as a whole.
    pub item: Option<&'a str>,
}

/// THE HOST SERVICES, as the kernel implements them. The dispatcher holds one for every instance it
pub trait HostServices: Send + Sync {
    /// Observe a declared chain's incarnation before the caller performs fresh planning reads.
    fn observe_chain_life(
        &self,
        _caller: &Caller,
        _kind: u32,
        _scope: &[u8],
        _done: Box<
            dyn FnOnce(Result<crate::abi::sdk::store::conditional::Expected, &'static str>) + Send,
        >,
    ) -> Result<(), &'static str> {
        Err("chain observation unsupported")
    }

    /// True only when the configured record store supports atomic conditional publication.
    fn supports_record_transactions(&self) -> bool {
        false
    }

    /// Submit an immutable logical candidate. Once accepted, custody belongs to the host even
    fn conditional_record_transaction(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _candidate: crate::abi::sdk::plane::conditional::ConditionalCandidate,
        _acked: Box<dyn FnOnce(crate::abi::sdk::plane::conditional::ConditionalResult) + Send>,
    ) -> Result<(), &'static str> {
        Err("conditional record transactions unsupported")
    }

    /// Optional, negotiated generic host observations. This Rust-only extension does not add a
    fn inspect(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _query: &crate::abi::mechanism::inspection::InspectionQuery,
    ) -> crate::abi::mechanism::inspection::InspectionResult {
        Err(crate::abi::mechanism::inspection::InspectionError::Unsupported)
    }

    /// `clock.now`: the kernel's one clock. Never pends.
    fn now(&self) -> Reading;

    /// `dest.judge`: judge `dest` against egress class `class`'s rules; `flags` = the caller's
    fn dest_judge(&self, dest: &str, class: u32, flags: u32, later: Option<Later>) -> Ran;

    /// `records.get`: `caller`'s record of `kind` under `key`, its own queued writes first.
    fn records_get(&self, caller: &Caller, kind: &str, key: &[u8], later: Later) -> Ran;

    /// `records.list`: `caller`'s records of `kind` under `prefix`, after `after`, in key order, at
    fn records_list(&self, caller: &Caller, list: RecordsList, later: Later) -> Ran;

    /// `records.claim`: put `key` of `kind` if absent, standing `ttl_ms` (never `0`). READY
    fn records_claim(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        ttl_ms: u64,
        later: Later,
    ) -> Ran;

    /// `sign`: sign `data` under `caller`'s declared signing domain. Span `0`: key = the key id,
    fn sign(&self, caller: &Caller, data: &[u8]) -> Stored;

    /// `trust.sight`: judge `hash`, the catalogue `counterparty` reports, against the kernel's trust
    fn trust_sight(&self, caller: &Caller, counterparty: &str, hash: &str, later: Later) -> Ran;

    /// `trust.sight` with `TRUST_UNREACHABLE`: the plane could not reach `counterparty`. READY with
    fn trust_unreached(&self, caller: &Caller, counterparty: &str) -> Stored;

    /// `trust.sight_item`: record the digest `item` of `counterparty` is offered at now (the
    fn trust_sight_item(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: &str,
        digest: &str,
    ) -> Stored;

    /// `trust.decide`: the operator's decision (`approve`, at `expected` when stated) about the
    fn trust_decide(
        &self,
        caller: &Caller,
        key: TrustKeyRef<'_>,
        expected: Option<&str>,
        approve: bool,
    ) -> Stored;

    /// `trust.state`: the kernel's trust state of `counterparty` and its items (a `KEY_*` value;
    fn trust_state(&self, caller: &Caller, counterparty: &str) -> Stored;

    /// `trust.serves`: THE KERNEL'S APPROVE as a query: whether `counterparty` serves `item`
    fn trust_serves(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: Option<&str>,
        digest: Option<&str>,
    ) -> Stored;

    /// `trust.due`: the counterparties of `caller` the kernel's tick marked for re-verification, one
    fn trust_due(&self, caller: &Caller) -> Stored;

    /// `trust.verify`: verify `signatures` (a JSON array as the document wrote it; empty = none)
    fn trust_verify(
        &self,
        caller: &Caller,
        counterparty: &str,
        payload: &[u8],
        signatures: &[u8],
    ) -> Stored;

    /// `entitlement.check`: whether the principal of `unit` (the unit the calling crossing
    fn entitlement_check(&self, caller: &Caller, unit: Option<u64>, target: &str) -> Stored;

    /// `session.emit`: write `bytes`, unsolicited, on the open carrier session `session`, outside
    fn session_emit(&self, caller: &Caller, session: u64, bytes: &[u8]) -> Stored;

    /// `ticket.mint`: mint a ticket for the principal of `unit` (the unit the calling crossing
    fn ticket_mint(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        ttl_secs: u64,
        record: &[u8],
    ) -> Stored;

    /// `ticket.take`: the record of the ticket that admitted `unit`, once: READY `TICKET_TAKEN`
    fn ticket_take(&self, caller: &Caller, unit: Option<u64>) -> Stored;

    /// `random.fill`: `len` bytes from the kernel's CSPRNG, READY with exactly those bytes; `len`
    fn random_fill(&self, len: u64) -> Stored;

    /// `records.secret`: the secret of the host-held credential `id` of `kind`, and whether it is
    fn records_secret(&self, kind: &str, id: &str, later: Later) -> Ran;

    /// `unit.nest`: run `ask` as a nested unit, a child of `unit` (the unit the calling crossing
    fn unit_nest(&self, caller: &Caller, unit: Option<u64>, ask: NestAsk, later: Later) -> Ran;

    /// `work.open`: open a durable work handle of `kind` (a record kind `caller` declared) for the
    fn work_open(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        kind: &str,
        record: &[u8],
        later: Later,
    ) -> Ran;

    /// `work.find`: the handle `reference` names, within `caller` and the principal of `unit`.
    fn work_find(&self, caller: &Caller, unit: Option<u64>, reference: &[u8], later: Later) -> Ran;

    /// `work.settle`: settle `caller`'s live handle `handle` with its final `record`, from a
    fn work_settle(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        handle: u64,
        record: &[u8],
        later: Later,
    ) -> Ran;

    /// `work.resume`: bind `caller`'s handle `handle` to `unit`, whose principal must be the one the
    fn work_resume(&self, caller: &Caller, unit: Option<u64>, handle: u64, later: Later) -> Ran;

    /// `disk.append` (THE DESIGN, the host's bounded disk lane): append `bytes` to the
    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran;

    /// `verify.lookup`: `caller`'s own verify cache under `key`, single-flight. READY `VERIFY_HIT`
    fn verify_lookup(&self, caller: &Caller, key: &[u8], later: Later) -> Ran;

    /// `verify.store`: store `entry` under `key` in `caller`'s verify cache for `ttl_ms` (`0` = the
    fn verify_store(&self, caller: &Caller, key: &[u8], entry: &[u8], ttl_ms: u64) -> Stored;

    /// `content.scan`: pass `content` through the gates the unit `unit` (the unit the calling
    fn content_scan(&self, caller: &Caller, unit: Option<u64>, content: &[u8], later: Later)
        -> Ran;

    /// `hook.call`: run `ask` over the hook stage the unit `unit` binds (`None` = the crossing
    fn hook_call(&self, caller: &Caller, unit: Option<u64>, ask: HookAsk, later: Later) -> Ran;

    /// `snapshot.read`: the host's metric families of `scope` (`abi::host::service`'s
    fn snapshot_read(&self, caller: &Caller, scope: u32) -> Snapshot;
}

/// A `hook.call` request, as the host copied it out of the caller's `in` (validated:
/// `check_hook_call_in` and the prompt view's own rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookAsk {
    /// `HOOK_GATE` | `HOOK_REWRITE`.
    pub stage: u32,
    /// Where a rewrite chain resumes; `0` for a gate.
    pub from: u32,
    /// The prompt's system text; `None` = none.
    pub system: Option<String>,
    /// The prompt's messages, `(role, text)`, in order.
    pub messages: Vec<(String, String)>,
}

/// What `snapshot.read` answers, before the loader lays it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Snapshot {
    /// The families, in the host's order.
    Families(Vec<crate::export_calls::Family>),
    /// Not ready yet (the recorder is not installed): the caller answers "not ready, retry".
    NotReady,
    /// Refused, for this reason (the caller was not granted the snapshot, or the host has none).
    Refused(&'static str),
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
    /// HOW the host rotates a due file. The host applies it; the plugin's manifest only states the
    /// archives it wants kept (`declares.keep`), which [`DiskRotate::declared`] turns into this.
    pub rotate: DiskRotate,
}

/// How the host rotates a destination it finds due ([`DiskDest::rotate_at`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskRotate {
    /// Truncate the live file in place and append to it from empty: 1.5.5's request-log file sink
    /// ("roll over by truncation rather than a rename", its v1.5.5 `rotate_mb` size bound,
    /// lines 96-108 of the sink's module), one bounded file whose older lines are dropped.
    Truncate,
    /// Rename the live file into `<path>.1` .. `<path>.{keep}`, dropping the oldest archive past
    /// `keep`.
    Rename {
        /// How many archives a rotation keeps.
        keep: u32,
    },
}

impl DiskRotate {
    /// The rotation the host applies to a destination whose manifest declares `keep` for it
    #[must_use]
    pub const fn declared(keep: Option<u32>) -> Self {
        match keep {
            Some(0) => Self::Truncate,
            Some(keep) => Self::Rename { keep },
            None => DISK_ROTATE_UNDECLARED,
        }
    }
}

/// The rotation a destination gets when its manifest declares no `keep` for it: 1.5.5's
pub const DISK_ROTATE_UNDECLARED: DiskRotate = DiskRotate::Truncate;

/// How many archives the host keeps for a destination it rotates by rename without a declared
pub const DISK_KEEP: u32 = 9;

/// The settings key beside a destination that states its rotation threshold, in MiB: the host's
pub const DISK_ROTATE_KEY: &str = "rotate_mb";

/// The settings key beside a destination that states how many archives the OPERATOR keeps when it
pub const DISK_KEEP_KEY: &str = "keep";

/// What one `disk.append` did, as the disk lane reports it and the mechanism stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskReport {
    /// `0` = the bytes landed; else the failed step (`DISK_OPEN_FAILED` / `DISK_APPEND_FAILED`).
    pub step: u64,
    /// Whether the file was renamed to its first archive before the append. A truncation in place
    /// is not reported: 1.5.5's request-log sink reported none (lines 96-108 of the sink's module
    /// at v1.5.5).
    pub rotated: bool,
    /// The rotation steps that failed (`DISK_RETENTION_FAILED` | ...).
    pub faults: u8,
    /// For a failed step: why, in the operating system's words.
    pub error: &'static str,
}

impl DiskReport {
    /// The report as the mechanism stores it under the call's handle: READY or FAILED, the step in
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
            bytes: Vec::new(),
            spans: Vec::new(),
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
pub trait CredentialRead: Send + Sync {
    /// The secret and its liveness.
    fn read(&self, kind: &str, id: &str) -> (crate::redacted::Secret<String>, bool);

    /// Whether a read can be answered yet (a source set late cannot, until it is).
    fn installed(&self) -> bool {
        true
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

/// One service result, as the host stores it under its handle. Its bytes may carry a credential:
/// every copy wipes them on drop, and Debug never prints their contents.
#[derive(Clone, PartialEq, Eq)]
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

impl std::fmt::Debug for Stored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stored")
            .field("outcome", &self.outcome)
            .field("value", &self.value)
            .field("bytes", &"<redacted>")
            .field("spans", &self.spans)
            .field("error", &self.error)
            .finish()
    }
}

impl Drop for Stored {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.bytes.zeroize();
    }
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
            bytes: Vec::new(),
            spans: Vec::new(),
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

/// The decimal digits of a chained record's sequence in its listed key ([`chain_key`]).
pub const CHAIN_SEQ_DIGITS: usize = 20;

/// THE LISTED KEY of record `seq` of the chain `scope`, of a record kind its plane declares chained
#[must_use]
pub fn chain_key(scope: &[u8], seq: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(scope.len() + 1 + CHAIN_SEQ_DIGITS);
    key.extend_from_slice(scope);
    key.push(b'/');
    key.extend_from_slice(format!("{seq:020}").as_bytes());
    key
}

/// The chain and the sequence a listed key of a chained record kind names ([`chain_key`]); `None`
#[must_use]
pub fn chain_key_parts(key: &[u8]) -> Option<(&[u8], u64)> {
    let cut = key.len().checked_sub(CHAIN_SEQ_DIGITS + 1)?;
    let (scope, rest) = key.split_at(cut);
    if scope.is_empty() || rest.first() != Some(&b'/') {
        return None;
    }
    let digits = &rest[1..];
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let seq = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some((scope, seq))
}

#[cfg(test)]
#[path = "tests/services_tests.rs"]
mod tests;
