// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST SERVICES, AS THE KERNEL SERVES THEM (`BUSBAR-1.6.0.md` THE DESIGN, host services): the
//! implementations behind the `HostSlots` table. The plugin loader owns the mechanism (the result
//! stored per completion handle, the short-buffer re-call and its FAULT, the refusal of a may-pend
//! service called with no ticket); it is handed [`KernelServices`] at construction
//! (the dispatcher's `with_services`) and calls in here at most once per handle.
//!
//! * `clock.now` — the kernel's clock: wall time, and monotonic time from an origin fixed when the
//!   services are built.
//! * `dest.judge` — the ONE destination judge, the egress unit's (through `net_guard`): the
//!   metadata denylist, then the refusals the name decides,
//!   answered at once and before any resolution, as 1.5.5 answered them. Asked to resolve
//!   (`DEST_RESOLVE`), a name is resolved off the caller's thread, the call pends, and the address
//!   judgement decides what it answered; not asked, the name's own judgement is the verdict (the
//!   1.5.5 judgement of a destination named in a request argument, which resolved nothing).
//!
//! * `records.get` / `records.list` — the caller's records of a kind it declared, through the
//!   store's typed record reads ([`RecordReads`]), its own unacknowledged writes laid over them
//!   ([`PendingRecords`]): an instance reads what it wrote.
//! * `records.claim` — the ONE approval-redemption and replay-refusal path: a one-time put-if-absent
//!   with an expiry, through the store's single-use redemption (store v3 `REDEEM_PLANE_TOKEN`, which
//!   fails closed). The claimed token is the digest of an [`IdempotencyKey`] the kernel mints over
//!   `(instance, kind, key)`, so a caller's key never reaches the store and two instances never
//!   claim each other's keys.
//! * `sign` — the caller's bytes signed with the subkey this node's signing key derives for the
//!   caller's declared signing domain; the key id is its declared prefix and the key's id.
//! * `trust.sight` / `trust.due` — the kernel's trust state ([`TrustBook`]), judged from the
//!   caller's parsed trust entries; demotion and its clearing are written through the durable
//!   demotion record.
//!
//! EVERY CALLER-SCOPED SERVICE ANSWERS FROM WHAT [`KernelServices::admit`] REGISTERED for the
//! caller's instance: its record kinds, its signing declaration and its trust entries. Every
//! per-instance registry (these facts, the queued writes, the trust state, the claim digest, the
//! durable demotion rows) is
//! keyed by the instance's LABEL, never its plugin: two instances of one plugin never share one. An
//! instance never admitted is REFUSED, never served on a guess.
//!
//! THE EGRESS CLASS → RULES MAPPING IS THE KERNEL'S. [`KernelServices::new`] takes it whole: the
//! wiring that builds the table decides, per class, the guard policy and the denylist. To keep 1.5.5's
//! answers, the class a plane names for a request-argument judgement admits plaintext (1.5.5 judged
//! only the host there), and its `allow_private` is the target's own setting.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use busbar_contract::abi::host::service::{self as svc, ItemSpan, MAX_SPANS};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::caps::{IdempotencyKey, KernelSeal};
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::records::RecordStore;
use busbar_contract::services::{Caller, HostServices, Later, Ran, Reading, RecordsList, Stored};
use sha2::{Digest, Sha256};

use crate::host_records::{merge_list, PendingRecords, RecordReads};
use crate::plane::quarantine::DemotionRecord;
use crate::trust::book::{Effect, Sight, TrustBook, Unjudged};
use crate::trust::section::TrustEntry;

use crate::net_guard::{
    check_structure, pin_answer_under, split_url, AddressRefusal, Denylist, GuardPolicy,
    NetworkRefusal, Structure,
};

/// The rules `dest.judge` applies for one egress class.
#[derive(Debug, Clone)]
pub struct DestRules {
    /// The guard policy.
    pub policy: GuardPolicy,
    /// The metadata denylist, with the deployment's additions and carve-outs.
    pub denylist: Arc<Denylist>,
}

/// Where one resolution's answer goes: called once, from any thread. `Err` is a resolution failure,
/// not an empty answer.
pub type Resolved = Box<dyn FnOnce(Result<Vec<IpAddr>, String>) + Send>;

/// A resolver that answers off the caller's thread.
pub trait Resolve: Send + Sync {
    /// Resolve `host`, answering through `done` now or later, on any thread; never blocks the caller.
    fn resolve(&self, host: &str, done: Resolved);
}

/// The system resolver, one short-lived thread per resolution, so a slow name never holds a
/// dispatcher worker.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, done: Resolved) {
        let cell = Arc::new(Mutex::new(Some(done)));
        let mine = Arc::clone(&cell);
        let host = host.to_string();
        let spawned = std::thread::Builder::new()
            .name("busbar-resolve".into())
            .spawn(move || {
                let answer = (host.as_str(), 0)
                    .to_socket_addrs()
                    .map(|a| a.map(|s| s.ip()).collect())
                    .map_err(|e| e.to_string());
                if let Some(done) = take(&mine) {
                    done(answer);
                }
            });
        if spawned.is_err() {
            if let Some(done) = take(&cell) {
                done(Err("no resolver thread".into()));
            }
        }
    }
}

fn take(cell: &Mutex<Option<Resolved>>) -> Option<Resolved> {
    cell.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// Runs a store call off the caller's thread.
pub trait Offload: Send + Sync {
    /// Run `job` on any thread, now or when one is free; never blocks the caller.
    fn run(&self, job: Box<dyn FnOnce() + Send>);
}

/// One short-lived thread per call, so a slow store never holds a dispatcher worker.
#[derive(Debug, Default, Clone, Copy)]
pub struct ThreadOffload;

impl Offload for ThreadOffload {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        let cell = Arc::new(Mutex::new(Some(job)));
        let mine = Arc::clone(&cell);
        let spawned = std::thread::Builder::new()
            .name("busbar-service".into())
            .spawn(move || {
                let job = mine.lock().unwrap_or_else(|e| e.into_inner()).take();
                if let Some(job) = job {
                    job();
                }
            });
        if spawned.is_err() {
            let job = cell.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(job) = job {
                job();
            }
        }
    }
}

/// Signs for the `sign` service: the key id and the signature of `data` under the subkey derived
/// for `domain`; `None` when this node has no signing key.
pub trait SignKey: Send + Sync {
    /// Sign.
    fn sign(&self, domain: &str, data: &[u8]) -> Option<(String, Vec<u8>)>;
}

impl SignKey for crate::governance::GovState {
    fn sign(&self, domain: &str, data: &[u8]) -> Option<(String, Vec<u8>)> {
        self.sign_in_domain(domain, data)
            .map(|(kid, sig)| (kid, sig.to_vec()))
    }
}

/// An instance's signing declaration: the domain its subkey is derived for, and its key-id prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signing {
    /// The signing domain.
    pub domain: String,
    /// The key-id prefix.
    pub kid_prefix: String,
}

/// What an instance declared, registered at bind by [`KernelServices::admit`].
#[derive(Debug, Clone, Default)]
pub struct InstanceFacts {
    /// Its record kinds, each the schema its records are kept under.
    pub record_kinds: Vec<RecordSchemaId>,
    /// Its signing declaration; `None` = `sign` is refused.
    pub signing: Option<Signing>,
    /// Its trust entries, one per counterparty, as `trust::section` parsed them.
    pub trust: Vec<(String, TrustEntry)>,
}

/// The stores the records services reach.
struct Records {
    reads: Arc<dyn RecordReads>,
    claims: Arc<dyn RecordStore>,
    offload: Arc<dyn Offload>,
}

/// The wall clock, in milliseconds since the Unix epoch.
pub type WallMs = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// THE KERNEL'S HOST SERVICES.
pub struct KernelServices {
    origin: Instant,
    classes: HashMap<u32, DestRules>,
    resolver: Arc<dyn Resolve>,
    wall_ms: WallMs,
    instances: Mutex<HashMap<Arc<str>, Arc<InstanceFacts>>>,
    records: Option<Records>,
    pending: Arc<PendingRecords>,
    signer: Option<Arc<dyn SignKey>>,
    trust: TrustBook,
    demotions: Option<Demotions>,
}

/// The durable demotion record, and the instance its unprefixed rows belong to.
struct Demotions {
    record: Arc<DemotionRecord>,
    default_instance: Arc<str>,
}

impl std::fmt::Debug for KernelServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelServices")
            .field("classes", &self.classes.len())
            .finish_non_exhaustive()
    }
}

impl KernelServices {
    /// The services over `classes` (egress class → rules; a class not listed is refused) and
    /// `resolver`.
    #[must_use]
    pub fn new(classes: HashMap<u32, DestRules>, resolver: Arc<dyn Resolve>) -> Self {
        Self {
            origin: Instant::now(),
            classes,
            resolver,
            wall_ms: Arc::new(system_wall_ms),
            instances: Mutex::default(),
            records: None,
            pending: Arc::default(),
            signer: None,
            trust: TrustBook::default(),
            demotions: None,
        }
    }

    /// Serve the records services over `reads` (the store's typed record reads) and `claims` (its
    /// single-use redemption), running each call through `offload`. Without it they are REFUSED.
    #[must_use]
    pub fn with_records(
        mut self,
        reads: Arc<dyn RecordReads>,
        claims: Arc<dyn RecordStore>,
        offload: Arc<dyn Offload>,
    ) -> Self {
        self.records = Some(Records {
            reads,
            claims,
            offload,
        });
        self
    }

    /// Serve `sign` with `signer`. Without it `sign` is REFUSED.
    #[must_use]
    pub fn with_signer(mut self, signer: Arc<dyn SignKey>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Write demotions and their clearing through `demotions`, and replay its rows at admit. Every
    /// row is keyed by [`demotion_key`], the instance's label and the counterparty. A row without
    /// the label (one a single-instance deployment wrote) belongs to `default_instance` alone, the
    /// instance the configuration upgrade maps that deployment's plane to; no other instance reads it.
    #[must_use]
    pub fn with_demotions(
        mut self,
        demotions: Arc<DemotionRecord>,
        default_instance: &str,
    ) -> Self {
        self.demotions = Some(Demotions {
            record: demotions,
            default_instance: Arc::from(default_instance),
        });
        self
    }

    /// Read the wall clock through `wall_ms`.
    #[must_use]
    pub fn with_wall_clock(mut self, wall_ms: WallMs) -> Self {
        self.wall_ms = wall_ms;
        self
    }

    /// Register (or re-register) what the instance labelled `instance` declared. Every
    /// caller-scoped service answers from this; its trust entries are admitted to the trust state,
    /// and its own durable demotions replayed.
    pub fn admit(&self, instance: &str, facts: InstanceFacts) {
        let key: Arc<str> = Arc::from(instance);
        let (rows, default) = self.demotions.as_ref().map_or_else(
            || (Vec::new(), false),
            |d| (d.record.list(), *d.default_instance == *instance),
        );
        let prefix = demotion_key(instance, "");
        let replayed = rows.iter().filter_map(|r| {
            let counterparty = match r.server.strip_prefix(prefix.as_str()) {
                Some(cp) => cp,
                None if default && !r.server.contains(DEMOTION_SEP) => r.server.as_str(),
                None => return None,
            };
            Some((counterparty, r.recorded_at.saturating_mul(1000)))
        });
        self.trust
            .admit(&key, facts.trust.iter().cloned(), replayed);
        self.lock_instances().insert(key, Arc::new(facts));
    }

    /// The overlay of every instance's unacknowledged record writes, which the plane driver's
    /// write-behind batcher fills and drains.
    #[must_use]
    pub fn pending(&self) -> &Arc<PendingRecords> {
        &self.pending
    }

    /// The kernel tick's re-verification mark, at the wall clock.
    pub fn mark_due(&self) {
        self.trust.mark_due((self.wall_ms)());
    }

    fn lock_instances(&self) -> std::sync::MutexGuard<'_, HashMap<Arc<str>, Arc<InstanceFacts>>> {
        self.instances.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn facts(&self, caller: &Caller) -> Option<Arc<InstanceFacts>> {
        self.lock_instances().get(&caller.instance).cloned()
    }

    /// The caller's facts and its declared schema for `kind`, and the stores; or the refusal.
    fn scope(&self, caller: &Caller, kind: &str) -> Result<(RecordSchemaId, &Records), Stored> {
        let facts = self
            .facts(caller)
            .ok_or_else(|| Stored::refused(NOT_ADMITTED))?;
        let schema = facts
            .record_kinds
            .iter()
            .find(|k| k.as_str() == kind)
            .copied()
            .ok_or_else(|| Stored::refused(NOT_A_KIND))?;
        let records = self
            .records
            .as_ref()
            .ok_or_else(|| Stored::refused(NO_STORE))?;
        Ok((schema, records))
    }
}

/// The refusal of a caller-scoped service from an instance never admitted.
pub const NOT_ADMITTED: &str = "the instance is not admitted";
/// The refusal of a record kind the caller did not declare.
pub const NOT_A_KIND: &str = "not a record kind the instance declared";
/// The refusal of a records service on a host with no store bound.
pub const NO_STORE: &str = "no store is bound";
/// The refusal of a claim with no time to live; there is no default.
pub const NO_TTL: &str = "a claim states its time to live";
/// The refusal of a claim whose expiry does not fit the clock.
pub const EXPIRY_OVERFLOW: &str = "the claim's expiry overflows";
/// The refusal of `sign` for an instance that declares no signing domain.
pub const NO_DOMAIN: &str = "the instance declares no signing domain";
/// The refusal of `sign` on a node with no signing key.
pub const NO_KEY: &str = "no signing key is configured";
/// The refusal of `trust.sight` for a counterparty the instance does not declare.
pub const NOT_A_COUNTERPARTY: &str = "not a counterparty the instance declares";
/// The FAILED answer of a store call that did not answer.
pub const STORE_FAILED: &str = "the store did not answer";

/// FAILED for `why`, nothing written.
fn failed(why: &'static str) -> Stored {
    Stored {
        outcome: Outcome::Failed,
        ..Stored::refused(why)
    }
}

/// Records as one answer: key then value per record, one span each.
fn spans_of(rows: Vec<(Vec<u8>, Vec<u8>)>) -> Stored {
    let mut stored = Stored::ready(0);
    for (k, v) in rows {
        let key_off = stored.bytes.len();
        stored.bytes.extend_from_slice(&k);
        let value_off = stored.bytes.len();
        stored.bytes.extend_from_slice(&v);
        stored
            .spans
            .push(span(key_off, k.len(), value_off, v.len()));
    }
    stored
}

fn span(key_off: usize, key_len: usize, value_off: usize, value_len: usize) -> ItemSpan {
    let n = |x: usize| u32::try_from(x).unwrap_or(u32::MAX);
    ItemSpan {
        key_off: n(key_off),
        key_len: n(key_len),
        value_off: n(value_off),
        value_len: n(value_len),
    }
}

/// The separator between the instance label and the counterparty in a demotion row's key: the
/// ASCII unit separator, which no configured label carries.
pub const DEMOTION_SEP: char = '\u{1f}';

/// The durable demotion row key of `counterparty` as seen by the instance labelled `instance`: two
/// instances never share a row, even for counterparties of one name.
#[must_use]
pub fn demotion_key(instance: &str, counterparty: &str) -> String {
    format!("{instance}{DEMOTION_SEP}{counterparty}")
}

/// The token a claim spends: the hex digest of the [`IdempotencyKey`] minted over the caller's
/// instance, the kind and the key, each separated by a zero byte.
#[must_use]
pub fn claim_token(instance: &str, kind: &str, key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(instance.as_bytes());
    h.update([0]);
    h.update(kind.as_bytes());
    h.update([0]);
    h.update(key);
    let minted = IdempotencyKey::mint(&KernelSeal::acquire_for_kernel(), h.finalize().into());
    hex::encode(minted.bytes())
}

impl HostServices for KernelServices {
    fn now(&self) -> Reading {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        Reading {
            wall_ns: wall,
            mono_ns: u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX),
        }
    }

    fn dest_judge(&self, dest: &str, class: u32, resolve: bool, later: Option<Later>) -> Ran {
        let Some(rules) = self.classes.get(&class) else {
            return Ran::Now(Stored::refused("no such egress class"));
        };
        match check_structure(dest, &[], rules.policy, &rules.denylist) {
            Err(r) => return Ran::Now(Stored::ready(verdict(dest, &r))),
            Ok(Structure::Name { .. }) if resolve => {}
            Ok(_) => return Ran::Now(Stored::ready(svc::DEST_ALLOWED)),
        }
        let Some(later) = later else {
            return Ran::Now(Stored::refused(
                "a service that may pend is callable only inside a ticketed op",
            ));
        };
        // The one judge; the verdict is its answer with the pinned address dropped.
        let answer =
            |v: Result<SocketAddr, u64>| Stored::ready(v.map_or_else(|v| v, |_| svc::DEST_ALLOWED));
        match self.judge_dial(dest, class, Box::new(move |v| later(answer(v)))) {
            Some(v) => Ran::Now(answer(v)),
            None => Ran::Later,
        }
    }

    fn records_get(&self, caller: &Caller, kind: &str, key: &[u8], later: Later) -> Ran {
        let (schema, records) = match self.scope(caller, kind) {
            Ok(s) => s,
            Err(refused) => return Ran::Now(refused),
        };
        let found = |v: Vec<u8>| {
            let len = v.len();
            let mut s = Stored::ready(svc::FOUND);
            s.bytes = v;
            s.spans.push(ItemSpan {
                key_off: svc_absent(),
                key_len: 0,
                ..span(0, 0, 0, len)
            });
            s
        };
        match self.pending.get(&caller.instance, kind, key) {
            Some(Some(v)) => return Ran::Now(found(v)),
            Some(None) => return Ran::Now(Stored::ready(svc::ABSENT)),
            None => {}
        }
        let reads = Arc::clone(&records.reads);
        let key = key.to_vec();
        records.offload.run(Box::new(move || {
            later(match reads.record_get(schema, &key) {
                Ok(Some(v)) => found(v.as_slice().to_vec()),
                Ok(None) => Stored::ready(svc::ABSENT),
                Err(_) => failed(STORE_FAILED),
            });
        }));
        Ran::Later
    }

    fn records_list(&self, caller: &Caller, list: RecordsList, later: Later) -> Ran {
        let (schema, records) = match self.scope(caller, &list.kind) {
            Ok(s) => s,
            Err(refused) => return Ran::Now(refused),
        };
        let cap = usize::try_from(MAX_SPANS).unwrap_or(usize::MAX);
        let limit = match list.limit {
            0 => cap,
            n => (n as usize).min(cap),
        };
        let queued = self
            .pending
            .under(&caller.instance, &list.kind, &list.prefix);
        let reads = Arc::clone(&records.reads);
        records.offload.run(Box::new(move || {
            // The store's scan has no cursor: the whole prefix is read, and `after` and `limit`
            // are applied here, over the store's rows and the queued writes together.
            later(match reads.record_scan(schema, &list.prefix, u32::MAX) {
                Ok(rows) => {
                    let rows = rows
                        .into_iter()
                        .map(|(k, v)| (k, v.as_slice().to_vec()))
                        .collect();
                    spans_of(merge_list(rows, queued, list.after.as_deref(), limit))
                }
                Err(_) => failed(STORE_FAILED),
            });
        }));
        Ran::Later
    }

    fn records_claim(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        ttl_ms: u64,
        later: Later,
    ) -> Ran {
        let (_, records) = match self.scope(caller, kind) {
            Ok(s) => s,
            Err(refused) => return Ran::Now(refused),
        };
        if ttl_ms == 0 {
            return Ran::Now(Stored::refused(NO_TTL));
        }
        let now_ms = (self.wall_ms)();
        let Some(expires_ms) = now_ms.checked_add(ttl_ms) else {
            return Ran::Now(Stored::refused(EXPIRY_OVERFLOW));
        };
        // The store keeps whole seconds: the expiry rounds up, so a claim never lapses early.
        let now = now_ms / 1000;
        let expires_at = expires_ms.div_ceil(1000);
        let token = claim_token(&caller.instance, kind, key);
        let claims = Arc::clone(&records.claims);
        let kind = kind.to_string();
        records.offload.run(Box::new(move || {
            later(
                match claims.redeem_plane_token(&kind, &token, expires_at, now) {
                    Ok(true) => Stored::ready(svc::CLAIM_WON),
                    Ok(false) => Stored::ready(svc::CLAIM_TAKEN),
                    Err(_) => failed(STORE_FAILED),
                },
            );
        }));
        Ran::Later
    }

    fn sign(&self, caller: &Caller, data: &[u8]) -> Stored {
        let Some(facts) = self.facts(caller) else {
            return Stored::refused(NOT_ADMITTED);
        };
        let Some(signing) = facts.signing.as_ref() else {
            return Stored::refused(NO_DOMAIN);
        };
        let Some((kid, sig)) = self
            .signer
            .as_ref()
            .and_then(|s| s.sign(&signing.domain, data))
        else {
            return Stored::refused(NO_KEY);
        };
        spans_of(vec![(
            format!("{}{kid}", signing.kid_prefix).into_bytes(),
            sig,
        )])
    }

    fn trust_sight(&self, caller: &Caller, counterparty: &str, hash: &str, later: Later) -> Ran {
        let (sight, effect) =
            match self
                .trust
                .sight(&caller.instance, counterparty, hash, (self.wall_ms)())
            {
                Ok(v) => v,
                Err(Unjudged::UnknownInstance) => return Ran::Now(Stored::refused(NOT_ADMITTED)),
                Err(Unjudged::UnknownCounterparty) => {
                    return Ran::Now(Stored::refused(NOT_A_COUNTERPARTY))
                }
            };
        if let Some(d) = self.demotions.as_ref() {
            let key = demotion_key(&caller.instance, counterparty);
            let settle = |server: &str, state| {
                crate::plane::quarantine::settle(&d.record, server, state);
            };
            match effect {
                Effect::Demote => settle(&key, crate::trust::TrustState::Quarantined),
                Effect::Clear => {
                    settle(&key, crate::trust::TrustState::Approved);
                    // The default instance also clears the unprefixed row it was replayed from.
                    if caller.instance == d.default_instance {
                        settle(counterparty, crate::trust::TrustState::Approved);
                    }
                }
                Effect::None => {}
            }
        }
        let _ = later;
        Ran::Now(Stored::ready(match sight {
            Sight::New => svc::TRUST_NEW,
            Sight::Same => svc::TRUST_SAME,
            Sight::Drifted => svc::TRUST_DRIFTED,
            Sight::Quarantined => svc::TRUST_QUARANTINED,
        }))
    }

    fn trust_due(&self, caller: &Caller) -> Stored {
        let Some(names) = self.trust.due(&caller.instance) else {
            return Stored::refused(NOT_ADMITTED);
        };
        let mut stored = Stored::ready(0);
        for n in names {
            let off = stored.bytes.len();
            stored.bytes.extend_from_slice(n.as_bytes());
            stored.spans.push(ItemSpan {
                value_off: svc_absent(),
                value_len: 0,
                ..span(off, n.len(), 0, 0)
            });
        }
        stored
    }
}

/// Where a dial's judgement goes when it pended: the pinned address, or the `DEST_*` verdict that
/// refused it. Called once, from any thread.
pub type Judged = Box<dyn FnOnce(Result<SocketAddr, u64>) + Send>;

impl KernelServices {
    /// THE ONE JUDGE, for a dial: `dest` against egress class `class`'s rules, and the address to
    /// dial — exactly the one the judgement pinned, so nothing resolves the name a second time. A
    /// refusal the name decides, and an IP literal, answer at once (`Some`) before any resolution;
    /// a name is resolved off the caller's thread and `done` gets the pin or the refusal (`None`).
    /// `dest.judge` is this judgement with the address dropped. An unknown class is refused as
    /// naming no usable host.
    pub fn judge_dial(
        &self,
        dest: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, u64>> {
        let Some(rules) = self.classes.get(&class) else {
            return Some(Err(svc::DEST_NO_HOST));
        };
        let (host, port, https) = match check_structure(dest, &[], rules.policy, &rules.denylist) {
            Err(r) => return Some(Err(verdict(dest, &r))),
            Ok(Structure::Pinned(p)) => return Some(Ok(p.socket_addr())),
            Ok(Structure::Name { host, port, https }) => (host, port, https),
        };
        let policy = rules.policy;
        let denylist = Arc::clone(&rules.denylist);
        let name = host.clone();
        self.resolver.resolve(
            &name,
            Box::new(move |answer| {
                done(match answer {
                    Err(_) => Err(svc::DEST_UNRESOLVABLE),
                    Ok(addrs) => pin_answer_under(&host, port, https, &addrs, policy, &denylist)
                        .map(|p| p.socket_addr())
                        .map_err(|r| guard_verdict(&r)),
                });
            }),
        );
        None
    }
}

/// An absent span's offset.
const fn svc_absent() -> u32 {
    busbar_contract::abi::mechanism::check::SPAN_ABSENT
}

/// The verdict a refusal answers. A destination naming a scheme the web schemes do not cover reads
/// as a bare authority to the one judge and is refused for its host; its verdict names the scheme,
/// as the refusal it is.
fn verdict(dest: &str, r: &NetworkRefusal) -> u64 {
    let foreign_scheme =
        dest.contains("://") && matches!(split_url(dest), Err(AddressRefusal::Scheme { .. }));
    match r {
        NetworkRefusal::Guard(AddressRefusal::NoHost(_)) if foreign_scheme => svc::DEST_SCHEME,
        NetworkRefusal::MetadataDenied(_) => svc::DEST_METADATA,
        NetworkRefusal::Guard(g) => guard_verdict(g),
        NetworkRefusal::NotAnUpstream => svc::DEST_NO_HOST,
    }
}

fn guard_verdict(r: &AddressRefusal) -> u64 {
    match r {
        AddressRefusal::Scheme { .. } => svc::DEST_SCHEME,
        AddressRefusal::Plaintext { .. } => svc::DEST_PLAINTEXT,
        AddressRefusal::ObfuscatedHost(_) => svc::DEST_OBFUSCATED,
        AddressRefusal::MetadataName(_) | AddressRefusal::CloudMetadataAddress { .. } => {
            svc::DEST_METADATA
        }
        AddressRefusal::LoopbackName(_) | AddressRefusal::InternalAddress { .. } => {
            svc::DEST_INTERNAL
        }
        AddressRefusal::Unresolvable { .. } => svc::DEST_UNRESOLVABLE,
        AddressRefusal::NoAddresses(_) => svc::DEST_NO_ADDRESSES,
        _ => svc::DEST_NO_HOST,
    }
}

#[cfg(test)]
#[path = "tests/host_services_tests.rs"]
mod tests;
