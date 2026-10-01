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
//!   judgement decides what it answered; admitted, every address it judged is written, one span
//!   each, so the caller can state them as the set its dial must land on (`EstablishIn::within`).
//!   Not asked, the name's own judgement is the verdict (the 1.5.5 judgement of a destination named
//!   in a request argument, which resolved nothing).
//!
//! * `records.get` / `records.list` — the caller's records of a kind it declared, through the
//!   store's typed record reads ([`RecordRows`]), its own unacknowledged writes laid over them
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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use busbar_contract::abi::host::service::{self as svc, ItemSpan, MAX_SPANS};
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::caps::{IdempotencyKey, KernelSeal};
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::RecordStore;
use busbar_contract::services::{
    merge_list, Caller, HostServices, Later, Ran, Reading, RecordsList, Stored,
};
use sha2::{Digest, Sha256};

/// The refusal of a record write past the write queue's bound.
pub const QUEUE_FULL: &str = "the record write queue is full";

use crate::host_records::{
    record_key, Acked, Owed as WriteOwed, PendingRecords, RecordRows, Write, WriteBehind,
};
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

/// Runs store I/O off the calling thread, on a bounded pool.
pub trait Offload: Send + Sync {
    /// Submit `job`. A pool that refuses it drops it unrun; it never runs on the caller's thread.
    fn run(&self, job: Box<dyn FnOnce() + Send>);
}

/// The runtime's blocking pool, with an explicit bound on the jobs it holds: at most `bound` are
/// queued or running at once, and a job past the bound is dropped unrun, which answers FAILED. The
/// runtime's `max_blocking_threads` bounds the threads under it; a runtime that is shutting down
/// drops a job unrun too.
#[derive(Debug, Clone)]
pub struct BlockingPool {
    handle: tokio::runtime::Handle,
    held: Arc<std::sync::atomic::AtomicUsize>,
    bound: usize,
}

impl BlockingPool {
    /// The blocking pool of the runtime `handle` drives, holding at most `bound` jobs.
    #[must_use]
    pub fn new(handle: tokio::runtime::Handle, bound: usize) -> Self {
        Self {
            handle,
            held: Arc::default(),
            bound,
        }
    }
}

/// One job the pool holds; releases its place however the job ends, run or dropped.
struct Place(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for Place {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

impl Offload for BlockingPool {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        use std::sync::atomic::Ordering;
        if self.held.fetch_add(1, Ordering::AcqRel) >= self.bound {
            self.held.fetch_sub(1, Ordering::AcqRel);
            // Past the bound: the job is dropped unrun, which answers FAILED.
            return;
        }
        let place = Place(Arc::clone(&self.held));
        // A runtime shutting down drops the job unrun, which answers FAILED; so does one the OS
        // will not give a thread, before the runtime's panic goes on.
        drop(self.handle.spawn_blocking(move || {
            let _place = place;
            job();
        }));
    }
}

/// A may-pend service's answer, owed through its [`Later`]. Dropped unanswered (its job was
/// refused by the pool and never ran) it answers FAILED, so a caller is never left waiting.
struct Owed(Option<Later>);

impl Owed {
    fn answer(mut self, stored: Stored) {
        if let Some(later) = self.0.take() {
            later(stored);
        }
    }
}

impl Drop for Owed {
    fn drop(&mut self) {
        if let Some(later) = self.0.take() {
            later(failed(POOL_REFUSED));
        }
    }
}

/// A flush the pool has not run yet. Dropped unrun (the pool refused it) it abandons the flush, so
/// the next write starts another.
struct Unrun(Option<Arc<WriteBehind>>);

impl Unrun {
    fn run(mut self) -> Option<Arc<WriteBehind>> {
        self.0.take()
    }
}

impl Drop for Unrun {
    fn drop(&mut self) {
        if let Some(batcher) = self.0.take() {
            batcher.abandon();
        }
    }
}

/// A claim's owed answer. Dropped unanswered (the pool refused its job) it answers Taken.
struct OwedClaim(Option<crate::host_claims::ClaimLater>);

impl OwedClaim {
    fn answer(mut self, claim: crate::host_claims::Claim) {
        if let Some(later) = self.0.take() {
            later(claim);
        }
    }
}

impl Drop for OwedClaim {
    fn drop(&mut self) {
        if let Some(later) = self.0.take() {
            later(crate::host_claims::Claim::Taken { until_ns: 0 });
        }
    }
}

/// Run `job` on `pool` and answer what it returns through `later`; FAILED if the pool refuses it.
fn submit(pool: &dyn Offload, later: Later, job: impl FnOnce() -> Stored + Send + 'static) -> Ran {
    let owed = Owed(Some(later));
    pool.run(Box::new(move || owed.answer(job())));
    Ran::Later
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
    /// The scope kinds its tail declares: `entitlement.check` answers only for these.
    pub scope_kinds: Vec<String>,
}

/// Why an instance was not admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitRefused {
    /// The label is longer than 65535 bytes or holds a control character: every per-instance key
    /// is built from it, and only a label without them keeps those keys apart.
    LabelUnfit {
        /// The label's length in bytes.
        len: usize,
    },
    /// Another instance holds the signing domain the instance declares.
    DomainHeld {
        /// The domain.
        domain: String,
        /// The instance holding it.
        held_by: String,
        /// The instance refused.
        asked_by: String,
    },
}

impl std::fmt::Display for AdmitRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LabelUnfit { len } => write!(
                f,
                "an instance label of {len} bytes is longer than 65535 bytes or holds a control \
                 character"
            ),
            Self::DomainHeld {
                domain,
                held_by,
                asked_by,
            } => write!(
                f,
                "instance `{asked_by}` declares the signing domain `{domain}`, which instance \
                 `{held_by}` holds: no instance signs as another"
            ),
        }
    }
}

impl std::error::Error for AdmitRefused {}

/// The stores the records services reach.
struct Records {
    reads: Arc<dyn RecordRows>,
    claims: Arc<dyn RecordStore>,
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
    pool: OnceLock<Arc<dyn Offload>>,
    pending: Arc<PendingRecords>,
    units: Arc<crate::host_units::UnitRecords>,
    batcher: Arc<WriteBehind>,
    signer: OnceLock<Arc<dyn SignKey>>,
    trust: TrustBook,
    demotions: OnceLock<Demotions>,
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
            pool: OnceLock::new(),
            pending: Arc::default(),
            units: Arc::default(),
            batcher: Arc::default(),
            signer: OnceLock::new(),
            trust: TrustBook::default(),
            demotions: OnceLock::new(),
        }
    }

    /// Serve the records services over `reads` (the store's typed record reads) and `claims` (its
    /// single-use redemption). Without them they are REFUSED.
    #[must_use]
    pub fn with_records(
        mut self,
        reads: Arc<dyn RecordRows>,
        claims: Arc<dyn RecordStore>,
    ) -> Self {
        self.records = Some(Records { reads, claims });
        self
    }

    /// Run every store call on `pool`, never on the calling thread. Without it the services that
    /// reach a store are REFUSED.
    #[must_use]
    pub fn with_pool(mut self, pool: Arc<dyn Offload>) -> Self {
        self.pool = OnceLock::from(pool);
        self
    }

    /// Serve `sign` with `signer`. Without it `sign` is REFUSED.
    #[must_use]
    pub fn with_signer(mut self, signer: Arc<dyn SignKey>) -> Self {
        self.signer = OnceLock::from(signer);
        self
    }

    /// Write demotions and their clearing through `demotions`, and replay its rows at admit. Every
    /// row is keyed by [`demotion_key`], the instance's label and the counterparty. A row without
    /// the label (one a single-instance deployment wrote) belongs to `default_instance` alone: the
    /// plane's implicit first instance, labelled with the plane's declared section key, which the
    /// kernel reads from the loaded configuration at boot. No other instance reads it.
    #[must_use]
    pub fn with_demotions(
        mut self,
        demotions: Arc<DemotionRecord>,
        default_instance: &str,
    ) -> Self {
        self.demotions = OnceLock::from(Demotions {
            record: demotions,
            default_instance: Arc::from(default_instance),
        });
        self
    }

    /// THE LATE ATTACH (ARCHITECT S7-TICK 2026-10-01, ruling A). The services are composed before
    /// any plugin is bound; the pool, the signer and the durable demotion record are built later,
    /// with the first app, and each lives for the process (an apply reuses all three). Each attaches
    /// ONCE, as its `with_*` would have set it; a second attach is refused (`false`) and changes
    /// nothing. Until attached, the services that need it answer REFUSED, as unattached.
    pub fn attach_pool(&self, pool: Arc<dyn Offload>) -> bool {
        self.pool.set(pool).is_ok()
    }

    /// The signer, attached late; see [`Self::attach_pool`].
    pub fn attach_signer(&self, signer: Arc<dyn SignKey>) -> bool {
        self.signer.set(signer).is_ok()
    }

    /// The durable demotion record, attached late, as [`Self::with_demotions`] states it; see
    /// [`Self::attach_pool`]. An instance admitted before it attached replayed no row.
    pub fn attach_demotions(&self, demotions: Arc<DemotionRecord>, default_instance: &str) -> bool {
        self.demotions
            .set(Demotions {
                record: demotions,
                default_instance: Arc::from(default_instance),
            })
            .is_ok()
    }

    fn pool(&self) -> Option<&dyn Offload> {
        self.pool.get().map(|p| &**p)
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
    ///
    /// `facts` are what the HOST read from the instance's signed Statement and its configured
    /// section, never bytes the plugin supplied: in particular the signing domain is the one the
    /// Statement declares, so no plugin names a domain it did not declare.
    ///
    /// # Errors
    ///
    /// [`AdmitRefused::LabelUnfit`] for a label longer than 65535 bytes or holding a control
    /// character; [`AdmitRefused::DomainHeld`] when another instance holds the signing domain it declares:
    /// no instance signs as another. Nothing is registered then.
    pub fn admit(&self, instance: &str, facts: InstanceFacts) -> Result<(), AdmitRefused> {
        if instance.len() > usize::from(u16::MAX) || instance.chars().any(char::is_control) {
            return Err(AdmitRefused::LabelUnfit {
                len: instance.len(),
            });
        }
        let key: Arc<str> = Arc::from(instance);
        let (rows, default) = self.demotions.get().map_or_else(
            || (Vec::new(), false),
            |d| (d.record.list(), *d.default_instance == *instance),
        );
        let mut instances = self.lock_instances();
        if let Some(domain) = facts.signing.as_ref().map(|s| s.domain.as_str()) {
            let holder = instances.iter().find(|(label, f)| {
                &***label != instance && f.signing.as_ref().is_some_and(|s| s.domain == domain)
            });
            if let Some((held_by, _)) = holder {
                return Err(AdmitRefused::DomainHeld {
                    domain: domain.to_string(),
                    held_by: held_by.to_string(),
                    asked_by: instance.to_string(),
                });
            }
        }
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
        instances.insert(key, Arc::new(facts));
        Ok(())
    }

    /// The record of every unit in flight, which the unit's admission writes and its end removes.
    #[must_use]
    pub fn units(&self) -> &Arc<crate::host_units::UnitRecords> {
        &self.units
    }

    /// WHETHER THE PRINCIPAL OF `unit` IS ENTITLED TO `target`, `"<scope_kind>:<name>"`, split at
    /// its first `:`: the kind must be one the caller's tail declares (otherwise NOT, with a debug
    /// diagnostic), and the answer is the one identity-and-grant judgement
    /// ([`crate::trust::validate::validate_visibility`]) over the unit's recorded principal: a dead
    /// or expired key is entitled to nothing, an ungoverned unit to everything. An unknown caller,
    /// a crossing that serves no unit, or a unit not in flight is entitled to nothing.
    #[must_use]
    pub fn entitled(&self, caller: &Caller, unit: Option<u64>, target: &str) -> bool {
        use crate::trust::validate::{validate_visibility, Grant};
        let Some(facts) = self.facts(caller) else {
            return false;
        };
        let Some((kind, name)) = target.split_once(':') else {
            return false;
        };
        if !facts.scope_kinds.iter().any(|k| k == kind) {
            crate::diagnostics::diag_debug!(
                crate::diagnostics::ENTITLEMENT_UNDECLARED_SCOPE_KIND,
                instance = %caller.instance,
                scope_kind = %kind,
                "an entitlement check named a scope kind this plane does not declare"
            );
            return false;
        }
        let Some(record) = unit.and_then(|u| self.units.get(u)) else {
            return false;
        };
        let now = (self.wall_ms)() / 1000;
        validate_visibility(
            record.principal.as_deref(),
            now,
            &[Grant::Scope { kind, name }],
        )
        .is_ok()
    }

    /// The overlay of every instance's record writes the store has not yet taken.
    #[must_use]
    pub fn pending(&self) -> &Arc<PendingRecords> {
        &self.pending
    }

    /// WRITE `value` under `key` of the caller's record kind `kind`: the instance reads it at once,
    /// the store takes it in the next batch, on the pool, and `acked` is answered only then (`Ok`,
    /// or the store's refusal). The write is durable before its writer hears so.
    ///
    /// # Errors
    ///
    /// The refusal, with `acked` never called: an instance never admitted, a kind it did not
    /// declare, no store or pool, or [`QUEUE_FULL`] (the overlay untouched).
    pub fn record_write(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        value: RecordBytes,
        acked: Acked,
    ) -> Result<(), &'static str> {
        let (schema, records, pool) = self.scope(caller, kind).map_err(|s| s.error)?;
        let pending = &self.pending;
        let started = self.batcher.push_with(|| {
            let seq = pending.enqueue(&caller.instance, kind, key, value.as_slice().to_vec());
            Write {
                instance: Arc::clone(&caller.instance),
                schema,
                key: key.to_vec(),
                value,
                seq,
                owed: WriteOwed::new(acked),
            }
        });
        match started {
            Some(true) => self.start_flush(records, pool),
            Some(false) => {}
            None => return Err(QUEUE_FULL),
        }
        Ok(())
    }

    /// The caller's record kind at `index` of its tail ([`RecordWrite::kind`] indexes it).
    ///
    /// [`RecordWrite::kind`]: busbar_contract::abi::plane::RecordWrite::kind
    #[must_use]
    pub fn record_kind(&self, caller: &Caller, index: u32) -> Option<RecordSchemaId> {
        let facts = self.facts(caller)?;
        facts.record_kinds.get(index as usize).copied()
    }

    /// CLAIM `(op, key)` for the instance labelled `instance` for `ttl_ms`, or, with `held`, extend
    /// the epoch it won. The kernel calls it on the instance's behalf (the inbound-auth replay claim
    /// is one: `held` is always `None`, so a second sighting inside the window is Taken and nothing
    /// extends it). The claim lives under the label the kernel derives from the instance's own
    /// ([`crate::host_claims::reserved_label`]), so an instance only contends with itself; the rule
    /// is [`crate::host_claims::decide`], run on the pool, answered through `later`. An answer
    /// that arrives after `deadline_ns` (the kernel's clock) is Taken for this caller, never a
    /// late Won. An instance never admitted, a zero `ttl_ms`, an empty `key`, or a host with no
    /// store or pool is Taken at once.
    #[allow(clippy::too_many_arguments)]
    pub fn claim_own(
        &self,
        instance: &str,
        op: &str,
        key: &[u8],
        ttl_ms: u64,
        held: Option<u64>,
        deadline_ns: u64,
        later: crate::host_claims::ClaimLater,
    ) -> crate::host_claims::Answer<crate::host_claims::Claim> {
        use crate::host_claims::{decide, reserved_label, Answer, Ask, Claim};
        let refused = Answer::Now(Claim::Taken { until_ns: 0 });
        if ttl_ms == 0 || key.is_empty() || !self.lock_instances().contains_key(instance) {
            return refused;
        }
        let (Some(records), Some(pool)) = (self.records.as_ref(), self.pool()) else {
            return refused;
        };
        let rows = Arc::clone(&records.reads);
        let tokens = Arc::clone(&records.claims);
        let wall_ms = Arc::clone(&self.wall_ms);
        let label = reserved_label(instance);
        let (op, key) = (op.to_string(), key.to_vec());
        let ttl_ns = ttl_ms.saturating_mul(1_000_000);
        let owed = OwedClaim(Some(later));
        pool.run(Box::new(move || {
            let now_ns = wall_ms().saturating_mul(1_000_000);
            let ask = Ask {
                label: &label,
                op: &op,
                key: &key,
                ttl_ns,
                held,
                now_ns,
            };
            let claim = decide(&*rows, &*tokens, &ask);
            let late = wall_ms().saturating_mul(1_000_000) > deadline_ns;
            owed.answer(match claim {
                Claim::Won { until_ns, .. } if late => Claim::Taken { until_ns },
                c => c,
            });
        }));
        Answer::Later
    }

    /// Run one flush of the record write queue on `pool`.
    fn start_flush(&self, records: &Records, pool: &dyn Offload) {
        let unrun = Unrun(Some(Arc::clone(&self.batcher)));
        let pending = Arc::clone(&self.pending);
        let rows = Arc::clone(&records.reads);
        pool.run(Box::new(move || {
            if let Some(batcher) = unrun.run() {
                batcher.flush(&pending, &*rows);
            }
        }));
    }

    /// The kernel tick's re-verification mark, at the wall clock.
    pub fn mark_due(&self) {
        self.trust.mark_due((self.wall_ms)());
    }

    /// The kernel tick, every [`crate::host_records::FLUSH_INTERVAL`]: start a flush of the queued
    /// record writes when none runs, so writes a refused flush left queued still reach the store.
    pub fn flush_tick(&self) {
        if let (Some(records), Some(pool)) = (self.records.as_ref(), self.pool()) {
            if self.batcher.start() {
                self.start_flush(records, pool);
            }
        }
    }

    /// GRACEFUL SHUTDOWN: flush every queued record write before the store closes, waiting up to
    /// `deadline`. `true` when all are written. Blocks: never call it on a dispatcher worker.
    pub fn drain(&self, deadline: std::time::Duration) -> bool {
        let until = Instant::now() + deadline;
        loop {
            if self.batcher.idle() {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            self.flush_tick();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    fn lock_instances(&self) -> std::sync::MutexGuard<'_, HashMap<Arc<str>, Arc<InstanceFacts>>> {
        self.instances.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn facts(&self, caller: &Caller) -> Option<Arc<InstanceFacts>> {
        self.lock_instances().get(&caller.instance).cloned()
    }

    /// The caller's declared schema for `kind`, the stores and the pool; or the refusal.
    fn scope(
        &self,
        caller: &Caller,
        kind: &str,
    ) -> Result<(RecordSchemaId, &Records, &dyn Offload), Stored> {
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
        let pool = self.pool().ok_or_else(|| Stored::refused(NO_POOL))?;
        Ok((schema, records, pool))
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
/// The refusal of a store-reaching service on a host with no pool bound.
pub const NO_POOL: &str = "no pool is bound";
/// The FAILED answer of a store call the pool refused to run.
pub const POOL_REFUSED: &str = "the pool refused the store call";
/// The FAILED answer of a store call that did not answer.
pub const STORE_FAILED: &str = "the store did not answer";
/// The refusal of a `random.fill` of no bytes or more than `MAX_RANDOM_FILL`.
pub const FILL_OUT_OF_RANGE: &str = "a fill asks for 1 to MAX_RANDOM_FILL bytes";
/// The FAILED answer of a `random.fill` the OS randomness source did not serve.
pub const NO_RANDOMNESS: &str = "the OS randomness source failed";

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
        key: Span {
            offset: n(key_off),
            len: n(key_len),
        },
        value: Span {
            offset: n(value_off),
            len: n(value_len),
        },
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
            Ok(_) if resolve => {}
            Ok(_) => return Ran::Now(Stored::ready(svc::DEST_ALLOWED)),
        }
        let Some(later) = later else {
            return Ran::Now(Stored::refused(
                "a service that may pend is callable only inside a ticketed op",
            ));
        };
        // The one judge; the verdict is its answer, and admitted, every address it judged.
        match self.judge(dest, class, Box::new(move |v| later(judged(v)))) {
            Some(v) => Ran::Now(judged(v)),
            None => Ran::Later,
        }
    }

    fn records_get(&self, caller: &Caller, kind: &str, key: &[u8], later: Later) -> Ran {
        let (schema, records, pool) = match self.scope(caller, kind) {
            Ok(s) => s,
            Err(refused) => return Ran::Now(refused),
        };
        let found = |v: Vec<u8>| {
            let len = v.len();
            let mut s = Stored::ready(svc::FOUND);
            s.bytes = v;
            s.spans.push(ItemSpan {
                key: absent_span(),
                ..span(0, 0, 0, len)
            });
            s
        };
        // An empty value is a tombstone: the record is absent.
        if let Some(v) = self.pending.get(&caller.instance, kind, key) {
            return Ran::Now(if v.is_empty() {
                Stored::ready(svc::ABSENT)
            } else {
                found(v)
            });
        }
        let reads = Arc::clone(&records.reads);
        let key = record_key(&caller.instance, key);
        submit(pool, later, move || match reads.record_get(schema, &key) {
            Ok(Some(v)) if !v.as_slice().is_empty() => found(v.as_slice().to_vec()),
            Ok(_) => Stored::ready(svc::ABSENT),
            Err(_) => failed(STORE_FAILED),
        })
    }

    fn records_list(&self, caller: &Caller, list: RecordsList, later: Later) -> Ran {
        let (schema, records, pool) = match self.scope(caller, &list.kind) {
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
        let scope = record_key(&caller.instance, &[]).len();
        let prefix = record_key(&caller.instance, &list.prefix);
        // The store's scan has no cursor: the whole prefix is read, and `after` and `limit` are
        // applied here, over the store's rows and the queued writes together.
        submit(pool, later, move || {
            match reads.record_scan(schema, &prefix, u32::MAX) {
                Ok(rows) => {
                    let rows = rows
                        .into_iter()
                        .filter_map(|(k, v)| {
                            Some((k.get(scope..)?.to_vec(), v.as_slice().to_vec()))
                        })
                        .collect();
                    spans_of(merge_list(rows, queued, list.after.as_deref(), limit))
                }
                Err(_) => failed(STORE_FAILED),
            }
        })
    }

    fn records_claim(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        ttl_ms: u64,
        later: Later,
    ) -> Ran {
        let (_, records, pool) = match self.scope(caller, kind) {
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
        submit(pool, later, move || {
            match claims.redeem_plane_token(&kind, &token, expires_at, now) {
                Ok(true) => Stored::ready(svc::CLAIM_WON),
                Ok(false) => Stored::ready(svc::CLAIM_TAKEN),
                Err(_) => failed(STORE_FAILED),
            }
        })
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
            .get()
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
        // A durable record with no pool to write it on: nothing is judged.
        let durable = match (self.demotions.get(), self.pool()) {
            (Some(_), None) => return Ran::Now(Stored::refused(NO_POOL)),
            (Some(d), Some(pool)) => Some((d, pool)),
            (None, _) => None,
        };
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
        let answer = Stored::ready(match sight {
            Sight::New => svc::TRUST_NEW,
            Sight::Same => svc::TRUST_SAME,
            Sight::Drifted => svc::TRUST_DRIFTED,
            Sight::Quarantined => svc::TRUST_QUARANTINED,
        });
        let Some((d, pool)) = durable.filter(|_| effect != Effect::None) else {
            return Ran::Now(answer);
        };
        // The durable write runs on the pool; the sighting answers once it is written.
        let record = Arc::clone(&d.record);
        let key = demotion_key(&caller.instance, counterparty);
        // The default instance also clears the unprefixed row it was replayed from.
        let unprefixed = (caller.instance == d.default_instance).then(|| counterparty.to_string());
        submit(pool, later, move || {
            let settle = |server: &str, state| {
                crate::plane::quarantine::settle(&record, server, state);
            };
            if effect == Effect::Demote {
                settle(&key, crate::trust::TrustState::Quarantined);
            } else {
                settle(&key, crate::trust::TrustState::Approved);
                if let Some(cp) = unprefixed {
                    settle(&cp, crate::trust::TrustState::Approved);
                }
            }
            answer
        })
    }

    fn entitlement_check(&self, caller: &Caller, unit: Option<u64>, target: &str) -> Stored {
        Stored::ready(if self.entitled(caller, unit, target) {
            svc::ENTITLED
        } else {
            svc::NOT_ENTITLED
        })
    }

    fn random_fill(&self, len: u64) -> Stored {
        if len == 0 || len > svc::MAX_RANDOM_FILL {
            return Stored::refused(FILL_OUT_OF_RANGE);
        }
        let mut bytes = vec![0; len as usize];
        if getrandom::fill(&mut bytes).is_err() {
            return failed(NO_RANDOMNESS);
        }
        Stored {
            bytes,
            ..Stored::ready(0)
        }
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
                value: absent_span(),
                ..span(off, n.len(), 0, 0)
            });
        }
        stored
    }
}

/// Where a dial's judgement goes when it pended: the pinned address, or the `DEST_*` verdict that
/// refused it. Called once, from any thread.
pub type Judged = Box<dyn FnOnce(Result<SocketAddr, u64>) + Send>;

/// THE ONE JUDGEMENT'S ANSWER: the pinned address and every address judged with it (the pin
/// first), or the `DEST_*` verdict refusing them.
type Admitted = Result<(SocketAddr, Vec<IpAddr>), u64>;

/// `dest.judge`'s stored answer for a judgement: the verdict, and admitted, one span per judged
/// address (key = the address as text, value absent).
fn judged(v: Admitted) -> Stored {
    let addrs = match v {
        Ok((_, addrs)) => addrs,
        Err(verdict) => return Stored::ready(verdict),
    };
    let mut s = Stored::ready(svc::DEST_ALLOWED);
    for a in addrs {
        let at = s.bytes.len();
        s.bytes.extend_from_slice(a.to_string().as_bytes());
        s.spans.push(ItemSpan {
            value: absent_span(),
            ..span(at, s.bytes.len() - at, 0, 0)
        });
    }
    s
}

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
        let pin = |v: Admitted| v.map(|(addr, _)| addr);
        self.judge(dest, class, Box::new(move |v| done(pin(v))))
            .map(pin)
    }

    /// The one judgement both [`Self::judge_dial`] and `dest.judge` read: [`Admitted`], at once
    /// (`Some`) or through `done` (`None`), on the terms `judge_dial` states.
    fn judge(
        &self,
        dest: &str,
        class: u32,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        let Some(rules) = self.classes.get(&class) else {
            return Some(Err(svc::DEST_NO_HOST));
        };
        let (host, port, https) = match check_structure(dest, &[], rules.policy, &rules.denylist) {
            Err(r) => return Some(Err(verdict(dest, &r))),
            Ok(Structure::Pinned(p)) => {
                let addr = p.socket_addr();
                return Some(Ok((addr, vec![addr.ip()])));
            }
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
                        .map(|p| (p.socket_addr(), addrs))
                        .map_err(|r| guard_verdict(&r)),
                });
            }),
        );
        None
    }
}

/// An absent span.
const fn absent_span() -> Span {
    Span {
        offset: busbar_contract::abi::mechanism::check::SPAN_ABSENT,
        len: 0,
    }
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
