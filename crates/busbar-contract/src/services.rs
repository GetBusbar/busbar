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
/// adopts; each slot validates the caller's `in`, applies the mechanism's rules, and calls in here
/// at most once per completion handle. Every service is required, with no default body (spec
/// #38(a)): an implementor that does not serve one says so in its own body, never by inheriting.
pub trait HostServices: Send + Sync {
    /// `clock.now`: the kernel's one clock. Never pends.
    fn now(&self) -> Reading;

    /// `dest.judge`: judge `dest` against egress class `class`'s rules; `flags` = the caller's
    /// `DEST_RESOLVE` | `DEST_REFUSE_PRIVATE` | `DEST_EXPLAIN`. Answers [`Ran::Now`] with a `DEST_*` verdict (or REFUSED for an unknown
    /// class), or hands `later` on and answers [`Ran::Later`]. `later` is `None` only for a call
    /// that may not pend, which never reaches here for this service.
    fn dest_judge(&self, dest: &str, class: u32, flags: u32, later: Option<Later>) -> Ran;

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

    /// `trust.sight` with `TRUST_UNREACHABLE`: the plane could not reach `counterparty`. READY with
    /// the LAST `TRUST_*` verdict, nothing changed. Never pends. Unserved by default.
    fn trust_unreached(&self, caller: &Caller, counterparty: &str) -> Stored {
        let _ = (caller, counterparty);
        Stored::refused(UNSERVED)
    }

    /// `trust.sight_item`: record the digest `item` of `counterparty` is offered at now (the
    /// plane's live re-fetch), READY with a `TRUST_*` sighting verdict. Never pends. Unserved by
    /// default.
    fn trust_sight_item(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: &str,
        digest: &str,
    ) -> Stored {
        let _ = (caller, counterparty, item, digest);
        Stored::refused(UNSERVED)
    }

    /// `trust.decide`: the operator's decision (`approve`, at `expected` when stated) about the
    /// calling instance's trust key `counterparty` (`item`: one item there), through the plane's
    /// own administrative verb. READY with the `TRUST_DECIDED_*` verdict after it, or an
    /// `UNDECIDED_*`. Never pends. Unserved by default.
    fn trust_decide(
        &self,
        caller: &Caller,
        key: TrustKeyRef<'_>,
        expected: Option<&str>,
        approve: bool,
    ) -> Stored {
        let _ = (caller, key, expected, approve);
        Stored::refused(UNSERVED)
    }

    /// `trust.state`: the kernel's trust state of `counterparty` and its items (a `KEY_*` value;
    /// one span per item, its value `<word>\0<approved>\0<seen>`). Never pends. Unserved by
    /// default.
    fn trust_state(&self, caller: &Caller, counterparty: &str) -> Stored {
        let _ = (caller, counterparty);
        Stored::refused(UNSERVED)
    }

    /// `trust.serves`: THE KERNEL'S APPROVE as a query: whether `counterparty` serves `item`
    /// (`None` = the counterparty as a whole) at `digest` (`None` = its last sighting). READY
    /// with `DISTRUST_NONE` or the `DISTRUST_*` that refuses it. Never pends. Unserved by default.
    fn trust_serves(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: Option<&str>,
        digest: Option<&str>,
    ) -> Stored {
        let _ = (caller, counterparty, item, digest);
        Stored::refused(UNSERVED)
    }

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

    /// `session.emit`: write `bytes`, unsolicited, on the open carrier session `session`, outside
    /// any unit: READY with nothing written back. A session that is not open, or not `caller`'s,
    /// is REFUSED. Unbilled; the host audits it as a session event under the session's verified
    /// principal. Never pends. A host that holds no carrier session refuses every one.
    fn session_emit(&self, caller: &Caller, session: u64, bytes: &[u8]) -> Stored {
        let _ = (caller, session, bytes);
        Stored::refused(UNSERVED)
    }

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

    /// `work.settle`: settle `caller`'s live handle `handle` with its final `record`, from a
    /// crossing serving `unit`. While a unit the handle was opened or resumed by is still in flight,
    /// only the principal it recorded settles it; a handle whose units have all ended settles by
    /// its instance. READY `0`.
    fn work_settle(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        handle: u64,
        record: &[u8],
        later: Later,
    ) -> Ran;

    /// `work.resume`: bind `caller`'s handle `handle` to `unit`, whose principal must be the one the
    /// handle recorded. READY `0`, span `0`'s key the state byte and its value the record.
    fn work_resume(&self, caller: &Caller, unit: Option<u64>, handle: u64, later: Later) -> Ran;

    /// `disk.append` (THE DESIGN, the host's bounded disk lane): append `bytes` to the
    /// file `dest` names, rotating it first when `dest` says it is due, OFF the caller's thread,
    /// and hand the [`DiskReport`] (as [`DiskReport::stored`]) to `later`. The loader has already
    /// mapped the caller's destination key to `dest`. A host with no disk lane refuses.
    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran;

    // THE APPEND ORDER IS THE LANDING ORDER (ARCHITECT H9): a later lander carries every service
    // above and appends its own below.

    /// `verify.lookup`: `caller`'s own verify cache under `key`, single-flight. READY `VERIFY_HIT`
    /// with span `0`'s value the stored entry; READY `VERIFY_LEAD` (the caller fetches, then
    /// `verify.store`s); or, while another caller leads, the answer pends until the leader stores
    /// and is READY `VERIFY_FOLLOW` with the leader's entry in span `0` (a leader that never
    /// stores loses its lead, and a follower is handed it as `VERIFY_LEAD`).
    fn verify_lookup(&self, caller: &Caller, key: &[u8], later: Later) -> Ran;

    /// `verify.store`: store `entry` under `key` in `caller`'s verify cache for `ttl_ms` (`0` = the
    /// host's default), ending any lead on it and answering its followers. READY `0`. Never pends.
    fn verify_store(&self, caller: &Caller, key: &[u8], entry: &[u8], ttl_ms: u64) -> Stored;

    /// `content.scan`: pass `content` through the gates the unit `unit` (the unit the calling
    /// crossing serves; `None` = it serves none, REFUSED) binds. READY `CONTENT_PASS` or
    /// `CONTENT_BLOCK`; the bytes, when written, the content as a gate rewrote it.
    fn content_scan(&self, caller: &Caller, unit: Option<u64>, content: &[u8], later: Later)
        -> Ran;

    /// `hook.call`: run `ask` over the hook stage the unit `unit` binds (`None` = the crossing
    /// serves none, REFUSED), pinned to the generation it was bound under. READY with the stage's
    /// `value` (`HookCallIn`'s), the bytes a rewrite or a stopping hook's words.
    fn hook_call(&self, caller: &Caller, unit: Option<u64>, ask: HookAsk, later: Later) -> Ran;

    /// `snapshot.read`: the host's metric families of `scope` (`abi::host::service`'s
    /// `SNAPSHOT_SCOPE_*`, a kind-neutral argument), lent only to the crossing the host granted
    /// them; the loader lays them out in the caller's buffer. Never pends.
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
    /// (`declares.keep`): `0` keeps no archive, so the file is truncated in place; `n` renames
    /// keeping `n` archives; none declared is [`DISK_ROTATE_UNDECLARED`].
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
/// truncation in place, the host's one default (a one-line change here and nowhere else).
pub const DISK_ROTATE_UNDECLARED: DiskRotate = DiskRotate::Truncate;

/// How many archives the host keeps for a destination it rotates by rename without a declared
/// `keep` (`<path>.1` .. `<path>.9`): the count [`DISK_ROTATE_UNDECLARED`] names when that default
/// is a rename (`DiskRotate::Rename { keep: DISK_KEEP }`).
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

// THE SHARED TEST DOUBLE IS NOT IN A RELEASE BUILD: [`HostServices`] with a refusing default per
// service, kept in step with the trait here. Compiled for this crate's own tests and, through the
// dev-only `services-double` feature, for a plugin's dev-dependency edge;
// `tests/test_seal_is_dev_only.rs` refuses any non-dev edge that enables it.
#[cfg(any(test, feature = "services-double"))]
#[path = "services_double.rs"]
pub mod double;
/// The decimal digits of a chained record's sequence in its listed key ([`chain_key`]).
pub const CHAIN_SEQ_DIGITS: usize = 20;

/// THE LISTED KEY of record `seq` of the chain `scope`, of a record kind its plane declares chained
/// (`abi::plane::RecordChain`): the scope, `/`, then the sequence in [`CHAIN_SEQ_DIGITS`]
/// zero-padded decimal digits, so key order within a chain is sequence order.
#[must_use]
pub fn chain_key(scope: &[u8], seq: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(scope.len() + 1 + CHAIN_SEQ_DIGITS);
    key.extend_from_slice(scope);
    key.push(b'/');
    key.extend_from_slice(format!("{seq:020}").as_bytes());
    key
}

/// The chain and the sequence a listed key of a chained record kind names ([`chain_key`]); `None`
/// for a key that names no record (a chain's break is announced by a span keyed by the bare scope).
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
