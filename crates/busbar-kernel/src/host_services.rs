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
//! * `trust.verify` — a document's detached signatures judged against the root key the caller's
//!   declared pin names ([`signed`]); the verdict and the refused name, never a fallback.
//! * `verify.lookup` / `verify.store` — the caller's own verify cache with single-flight
//!   leadership ([`crate::host_verify`]): hit, lead or follow; a lapsed lead passes on at the tick.
//! * `content.scan` / `hook.call` — the hook stage the unit the crossing serves bound
//!   ([`crate::host_units::UnitHookStage`]): its plane's and pool's gates and rewrite chain, at the
//!   generation it was bound under; never anything the caller names. They run only when the plane
//!   calls them: nothing here acts on carried content on its own (Law 11).
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
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use busbar_contract::abi::host::service::{self as svc, ItemSpan, MAX_SPANS};
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::caps::{IdempotencyKey, KernelSeal};
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::RecordStore;
use busbar_contract::services::{
    merge_list, Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, Reading, RecordsList,
    Stored,
};

/// The refusal of a record write past the write queue's bound.
pub const QUEUE_FULL: &str = "the record write queue is full";

use crate::host_records::{
    record_key, Acked, Owed as WriteOwed, PendingRecords, RecordRows, Write, WriteBehind,
};
use crate::host_units::StageAnswer;
use crate::host_work::{
    owner_of, parse_reference, reference_text, refusal as work_refusal, work_key, Owner, Work,
    WorkBook, WorkBounds, WORK_SCHEMA,
};
use crate::plane::quarantine::DemotionRecord;
use crate::trust::book::{
    Distrust, Effect, KeyRow, KeyState, Ruling, Sight, TrustBook, TrustFacts, Undecided, Unjudged,
};
use crate::trust::section::TrustEntry;
use crate::trust::signed;

/// THE DESTINATION JUDGE THE KERNEL ASKS (OWNER ruling DESTINATION GUARD): the connector's one
/// guard, installed by the root. The judge lives in the connector; the kernel names only this
/// trait, so the edge stays connector -> kernel.
pub trait DestJudge: Send + Sync {
    /// `dest` (a URL or `host[:port]`) under egress class `class`, without resolving: the scheme
    /// and name arms, an IP literal judged as its own answer. `refuse_private`: every private
    /// address and loopback name refused whatever the deployment's private-address setting and
    /// the class (`DEST_REFUSE_PRIVATE`). `Err` is the `DEST_*` verdict.
    ///
    /// # Errors
    ///
    /// The verdict refusing it.
    fn judge_name(&self, dest: &str, class: u32, refuse_private: bool) -> Result<(), u64>;
    /// `dest` judged and pinned, on [`Self::judge_name`]'s terms: at once (`Some`) for a literal
    /// or a refusal the name decides; a name is resolved off the caller's thread and `done` gets
    /// the answer (`None`). A refusal an address or the resolution decided names it
    /// ([`Refused::detail`]).
    fn judge(
        &self,
        dest: &str,
        class: u32,
        refuse_private: bool,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted>;
    /// [`Self::judge`] for a dial to a destination its need holds a PRIVATE REACH to (the
    /// registration's `abi::plane::TRUST_PRIVATE_REACH`, sealed per need and destination by the
    /// host): a private address it stands for is admitted as an allowlist entry naming its host
    /// would; a cloud-metadata address never is, and the class is unchanged. The default honours
    /// no reach (the class judges alone: fail-closed).
    fn judge_reaching(
        &self,
        dest: &str,
        class: u32,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        self.judge(dest, class, false, done)
    }
    /// An answer the kernel's own client resolved for `host`, judged whole under `class`.
    ///
    /// # Errors
    ///
    /// The refusal of the first refused address.
    fn judge_answer(&self, host: &str, addrs: &[IpAddr], class: u32) -> Result<(), DestRefusal>;
    /// The name arm for a `host` the kernel's own client is about to dial under `class`, before any
    /// resolution: an IP literal judged as its own answer, a metadata, blocked or `localhost` name
    /// decided here ([`Self::judge_name`]'s judgement, with the guard's sentence when it has one).
    ///
    /// # Errors
    ///
    /// The refusal.
    fn judge_host(&self, host: &str, class: u32) -> Result<(), DestRefusal> {
        self.judge_name(host, class, false)
            .map_err(|verdict| DestRefusal {
                verdict,
                reason: format!("host `{host}` was refused by the destination guard"),
            })
    }
    /// A config commit: the deployment's destinations are now `d`. A judge that re-reads its
    /// metadata lists at every commit (as 1.5.5 did) takes them from here; the default keeps what
    /// it was built with. Raised through the egress-trust capability the root installs the
    /// deployment's one guard behind (`plane_host::egress_trust::destinations_applied`), no static
    /// of its own (door-only:static-seam).
    fn destinations_applied(&self, d: &crate::config::Destinations) {
        let _ = d;
    }
}

/// A destination judge's refusal of an answer: the `DEST_*` verdict and the guard's sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestRefusal {
    /// The `DEST_*` verdict.
    pub verdict: u64,
    /// The guard's sentence.
    pub reason: String,
}

impl std::fmt::Display for DestRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for DestRefusal {}

/// THE ROOT'S NESTED-DISPATCH SEAM (THE DESIGN §11.12 unit row; ARCHITECT H3 "NestRoute root
/// seam"): `unit.nest` hands the composition root the child to run, and the root runs it on
/// whatever serves the claim it names, as a child of `parent` under its principal, its scope and its
/// admission chain. The kernel never learns what the child is.
pub trait NestRoute: Send + Sync {
    /// Run `nest`, and answer `done` once, from any thread, with the child's whole reply.
    fn nest(&self, nest: Nest, done: NestDone);
}

/// One nested unit, as the kernel hands it to the root.
#[derive(Debug, Clone)]
pub struct Nest {
    /// The parent unit, by the key the kernel minted for it.
    pub parent: u64,
    /// The child's depth: one more than its parent's.
    pub depth: u32,
    /// The parent's verified principal (`None` = ungoverned), the child's own.
    pub principal: Option<Arc<busbar_contract::records::VirtualKey>>,
    /// The claim and body.
    pub ask: NestAsk,
}

/// What a nested unit answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NestReply {
    /// The child ran (or was refused) and this is its whole reply: its status, head fields and
    /// body.
    Answered {
        /// The status.
        status: u32,
        /// The head fields, name and value.
        fields: Vec<(Vec<u8>, Vec<u8>)>,
        /// The body.
        body: Vec<u8>,
    },
    /// Nothing serves the claim, or the child could not be run; REFUSED with this reason.
    Unserved(&'static str),
}

/// Where a nested unit's reply goes, once.
pub type NestDone = Box<dyn FnOnce(NestReply) + Send>;

/// The deepest a nested unit may be (a unit a caller sent is depth 0).
pub const NEST_DEPTH_MAX: u32 = 3;
/// How many nested units may run at once on the node.
pub const NEST_CONCURRENCY: usize = 256;

/// The refusal of `unit.nest` from a crossing that serves no unit in flight.
pub const NEST_NO_UNIT: &str = "the crossing serves no unit in flight";
/// The refusal of `unit.nest` past [`NEST_DEPTH_MAX`].
pub const NEST_TOO_DEEP: &str = "the nested unit would be deeper than the nesting cap";
/// The refusal of `unit.nest` when [`NEST_CONCURRENCY`] nested units already run.
pub const NEST_FULL: &str = "the node runs as many nested units as it holds";
/// The refusal of `unit.nest` on services the root installed no nested-dispatch seam on.
pub const NO_NEST_ROUTE: &str = "no nested dispatch is installed";
/// The FAILED answer of a nested unit whose reply was dropped unanswered.
pub const NEST_DROPPED: &str = "the nested unit ended with no reply";
/// THE ONE JUDGEMENT'S REFUSAL: the `DEST_*` verdict, and what decided it when an address or the
/// resolution did (the refused address as text; the resolver's own reason), which `dest.judge`
/// writes for a caller that asks (`DEST_EXPLAIN`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// The `DEST_*` verdict.
    pub verdict: u64,
    /// The refused address, or the resolver's reason; `None` when the name alone decided it.
    pub detail: Option<String>,
}

impl From<u64> for Refused {
    fn from(verdict: u64) -> Self {
        Refused {
            verdict,
            detail: None,
        }
    }
}

/// What `dest.judge` answers on services built without a destination judge.
pub const NO_DEST_JUDGE: &str = "no destination judge is installed";

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

/// A nested unit's owed answer and its permit. Answered or dropped, the permit goes back once;
/// dropped unanswered it answers FAILED, so the parent is never left waiting.
struct OwedNest {
    later: Option<Later>,
    pool: Arc<crate::pump::NestedPool>,
    permit: Option<crate::pump::NestedPermit>,
}

impl OwedNest {
    fn answer(mut self, reply: NestReply) {
        self.release();
        if let Some(later) = self.later.take() {
            later(nested_answer(reply));
        }
    }

    fn release(&mut self) {
        if let Some(p) = self.permit.take() {
            self.pool.leave(p);
        }
    }
}

impl Drop for OwedNest {
    fn drop(&mut self) {
        self.release();
        if let Some(later) = self.later.take() {
            later(failed(NEST_DROPPED));
        }
    }
}

/// `unit.nest`'s stored answer: `value` = the status; span `0`'s value the body (its key absent),
/// each span after it one head field.
fn nested_answer(reply: NestReply) -> Stored {
    let (status, fields, body) = match reply {
        NestReply::Answered {
            status,
            fields,
            body,
        } => (status, fields, body),
        NestReply::Unserved(why) => return Stored::refused(why),
    };
    let mut s = Stored::ready(u64::from(status));
    let len = body.len();
    s.bytes = body;
    s.spans.push(ItemSpan {
        key: absent_span(),
        ..span(0, 0, 0, len)
    });
    // At most as many fields as one answer carries spans, beside the body's.
    let most = usize::try_from(MAX_SPANS).unwrap_or(usize::MAX) - 1;
    for (name, value) in fields.into_iter().take(most) {
        let at = s.bytes.len();
        s.bytes.extend_from_slice(&name);
        s.bytes.extend_from_slice(&value);
        s.spans
            .push(span(at, name.len(), at + name.len(), value.len()));
    }
    s
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
    /// Its chained record kinds, as its tail declares them (`PlaneTail::record_chains`, each `kind`
    /// an index into [`InstanceFacts::record_kinds`]): a record write of one is appended to the
    /// kernel's journal ([`crate::host_chains`]), never put.
    pub record_chains: Vec<busbar_contract::abi::plane::RecordChain>,
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
    /// The same store narrowed to its plane-record slots: where a chained kind's journal persists.
    plane: Arc<dyn crate::plane::store::PlaneStore>,
}

/// Every admitted instance's chained record kinds, by `(label, kind)`.
type Chains = HashMap<(Arc<str>, String), Arc<crate::host_chains::ChainedKind>>;

/// The wall clock, in milliseconds since the Unix epoch.
pub type WallMs = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The monotonic clock `clock.now` reads, in nanoseconds from the services' origin.
pub type MonoNs = Arc<dyn Fn() -> u64 + Send + Sync>;

/// THE LIVE RE-RESOLUTION of an admitted principal at `now` (Unix seconds): the principal as it
/// stands, or `None` when it no longer does.
pub type Standing = Arc<
    dyn Fn(
            &Arc<busbar_contract::records::VirtualKey>,
            u64,
        ) -> Option<Arc<busbar_contract::records::VirtualKey>>
        + Send
        + Sync,
>;

fn system_wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// THE KERNEL'S HOST SERVICES.
pub struct KernelServices {
    origin: Instant,
    wall_ms: WallMs,
    /// The monotonic clock, where one was given; else the time since [`Self::origin`].
    mono_ns: Option<MonoNs>,
    instances: Mutex<HashMap<Arc<str>, Arc<InstanceFacts>>>,
    /// Every admitted instance's chained record kinds, by `(label, kind)`; kept across a
    /// re-admission so a chain's positions are never reset.
    chains: Mutex<Chains>,
    records: OnceLock<Records>,
    pool: OnceLock<Arc<dyn Offload>>,
    pending: Arc<PendingRecords>,
    units: Arc<crate::host_units::UnitRecords>,
    batcher: Arc<WriteBehind>,
    signer: OnceLock<Arc<dyn SignKey>>,
    trust: TrustBook,
    /// The destination guard; when set it IS the judge (`dest.judge`, [`Self::judge_dial`]).
    judge: Option<Arc<dyn DestJudge>>,
    demotions: OnceLock<Demotions>,
    /// The work book behind `work.*`, and its bounds.
    work: Arc<WorkBook>,
    work_bounds: WorkBounds,
    /// Each instance's own work bounds (its section's `work:`), by label; [`Self::default_work_bounds`]
    /// where none is bound.
    bounds_of: Mutex<HashMap<Arc<str>, WorkBounds>>,
    /// The root's nested-dispatch seam, attached once, and the permits nested units run under.
    nest: OnceLock<Arc<dyn NestRoute>>,
    /// The live re-resolution of a unit's principal (a registry key by id, a role-bound one through
    /// the current bindings): `None` when it no longer stands. Attached by the composition root
    /// over its live snapshot; unattached, the principal admitted is the one judged.
    standing: OnceLock<Standing>,
    nested: Arc<crate::pump::NestedPool>,
    /// The bounded disk lane `disk.append` runs on (THE DESIGN §11.11 R4).
    disk: crate::host_disk::DiskLane,
    /// THE OPEN CARRIER SESSIONS (`session.emit`), by number: the instance each serves, its
    /// verified principal and the writer its unsolicited output goes to.
    sessions: Mutex<HashMap<u64, CarrierSession>>,
    /// The verify cache behind `verify.*`.
    verify: crate::host_verify::VerifyBook,
}

/// ONE OPEN CARRIER SESSION: a carrier the root holds open for one caller (a process's own
/// stdin/stdout), whose arrivals are each their own unit, and on which the instance serving it may
/// write unsolicited output (`session.emit`).
struct CarrierSession {
    /// The label of the instance whose claim the session is served on.
    instance: Arc<str>,
    /// The principal the session was bound to once, at its open.
    principal: String,
    /// The session's writer: `false` once the carrier can take nothing more.
    sink: CarrierSink,
}

/// Where a carrier session's unsolicited output is written: one whole write; `false` once the
/// carrier is gone.
pub type CarrierSink = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// The action word a carrier session's unsolicited write is audited under (`session.emit`).
pub const SESSION_EMIT_ACTION: &str = "session.emit";

/// `session.emit`'s refusal of a session that is not open, or not the calling instance's.
pub const SESSION_NOT_OPEN: &str = "no such carrier session is open for this instance";

/// The durable demotion record, and the instance its unprefixed rows belong to.
struct Demotions {
    record: Arc<DemotionRecord>,
    default_instance: Arc<str>,
}

impl Default for KernelServices {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for KernelServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelServices")
            .field("judge", &self.judge.is_some())
            .finish_non_exhaustive()
    }
}

impl KernelServices {
    /// The services, judging no destination until [`Self::with_dest_judge`] gives them the
    /// deployment's guard (every `dest.judge` refused, every dial refused, until then).
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
            wall_ms: Arc::new(system_wall_ms),
            mono_ns: None,
            instances: Mutex::default(),
            chains: Mutex::default(),
            records: OnceLock::new(),
            pool: OnceLock::new(),
            pending: Arc::default(),
            units: Arc::default(),
            batcher: Arc::default(),
            signer: OnceLock::new(),
            trust: TrustBook::default(),
            judge: None,
            demotions: OnceLock::new(),
            work: Arc::default(),
            work_bounds: WorkBounds::default(),
            bounds_of: Mutex::default(),
            nest: OnceLock::new(),
            standing: OnceLock::new(),
            nested: Arc::new(crate::pump::NestedPool::new(
                NEST_CONCURRENCY,
                NEST_DEPTH_MAX as usize + 1,
            )),
            disk: crate::host_disk::DiskLane::default(),
            sessions: Mutex::default(),
            verify: crate::host_verify::VerifyBook::default(),
        }
    }

    /// OPEN A CARRIER SESSION for `instance` (the label of the instance whose claim it is served
    /// on), bound to `principal`, its unsolicited output written through `sink`: the session's
    /// number, which its arrivals name (`abi::host::service::CARRIER_SESSION_FIELD`) and
    /// `session.emit` takes. Numbers are never reused within a process.
    pub fn open_carrier_session(&self, instance: &str, principal: &str, sink: CarrierSink) -> u64 {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let number = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                number,
                CarrierSession {
                    instance: Arc::from(instance),
                    principal: principal.to_string(),
                    sink,
                },
            );
        number
    }

    /// CLOSE carrier session `session`: an emit on it is refused from now on.
    pub fn close_carrier_session(&self, session: u64) {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&session);
    }

    /// THE NESTED-DISPATCH SEAM, attached late by the root once its door routes exist (see
    /// [`Self::attach_pool`]): once; a second attach is refused (`false`) and changes nothing.
    pub fn attach_nest(&self, route: Arc<dyn NestRoute>) -> bool {
        self.nest.set(route).is_ok()
    }

    /// Re-resolve every unit's principal through `standing` from now on (once; a second attach is
    /// refused): entitlement is judged against the principal as it stands, frame by frame.
    pub fn attach_standing(&self, standing: Standing) -> bool {
        self.standing.set(standing).is_ok()
    }

    /// The permits nested units run under (how many are out is `size - available`).
    #[must_use]
    pub fn nested(&self) -> &Arc<crate::pump::NestedPool> {
        &self.nested
    }

    /// Bound every instance's work at `bounds` (the legacy registries' bounds until then).
    #[must_use]
    pub fn with_work_bounds(mut self, bounds: WorkBounds) -> Self {
        self.work_bounds = bounds;
        self
    }

    /// The work book behind `work.*`.
    #[must_use]
    pub fn work(&self) -> &Arc<WorkBook> {
        &self.work
    }

    /// The host's work bounds: every instance's that binds none of its own.
    #[must_use]
    pub fn default_work_bounds(&self) -> WorkBounds {
        self.work_bounds
    }

    /// Bound the work of the instance labelled `instance` at `bounds` (its section's `work:`,
    /// [`WorkBounds::of_section`]); re-binding replaces them.
    pub fn bound_work(&self, instance: &str, bounds: WorkBounds) {
        self.bounds_of
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(Arc::from(instance), bounds);
    }

    /// The work bounds of the instance labelled `instance`: its own, else the host's.
    #[must_use]
    pub fn work_bounds_of(&self, instance: &str) -> WorkBounds {
        self.bounds_of
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(instance)
            .copied()
            .unwrap_or(self.work_bounds)
    }

    /// The same services judging every destination through `judge` (the connector's guard).
    #[must_use]
    pub fn with_dest_judge(mut self, judge: Arc<dyn DestJudge>) -> Self {
        self.judge = Some(judge);
        self
    }

    /// Serve the records services over `reads` (the store's typed record reads) and `claims` (its
    /// single-use redemption). Without them they are REFUSED.
    #[must_use]
    pub fn with_records(self, reads: Arc<dyn RecordRows>, claims: Arc<dyn RecordStore>) -> Self {
        self.attach_records(reads, claims);
        self
    }

    /// Serve the records services over `reads` and `claims` (see [`Self::with_records`]), attached
    /// late, once: the configured store is opened after the services are installed (the composition
    /// root's late attach). `false` when a record store was already bound.
    pub fn attach_records(&self, reads: Arc<dyn RecordRows>, claims: Arc<dyn RecordStore>) -> bool {
        let plane = crate::plane::store::PlaneStoreView::narrow(Arc::clone(&claims));
        self.records
            .set(Records {
                reads,
                claims,
                plane,
            })
            .is_ok()
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

    /// Read `clock.now`'s monotonic time through `mono_ns`.
    #[must_use]
    pub fn with_mono_clock(mut self, mono_ns: MonoNs) -> Self {
        self.mono_ns = Some(mono_ns);
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
        // The operator's kept trust decisions replay at the instance's FIRST admit only: a re-admit
        // keeps them in its state, and one whose declared pin changed is the operator's re-approval.
        let decided = if instances.contains_key(instance) {
            Vec::new()
        } else {
            self.demotions
                .get()
                .map(|d| d.record.decisions())
                .unwrap_or_default()
        };
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
        {
            let mut chains = self
                .chains
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for chain in &facts.record_chains {
                let Some(kind) = facts.record_kinds.get(chain.kind as usize) else {
                    continue;
                };
                let slot = (Arc::clone(&key), kind.as_str().to_string());
                if chains.contains_key(&slot) {
                    continue;
                }
                if let Some(chained) = crate::host_chains::ChainedKind::new(kind.as_str(), chain) {
                    chains.insert(slot, Arc::new(chained));
                }
            }
        }
        self.trust.admit_decided(instance, &decided);
        instances.insert(key, Arc::new(facts));
        Ok(())
    }

    /// THE KERNEL'S APPROVE over the trust facts a plane stated for a unit of `instance`
    /// ([`TrustBook::judge`]; ARCHITECT 2026-10-06: trust is the kernel's Approve step).
    ///
    /// # Errors
    ///
    /// The [`Distrust`] that refuses the unit.
    pub fn trust_judge(&self, instance: &str, facts: &TrustFacts<'_>) -> Result<(), Distrust> {
        self.trust.judge(instance, facts)
    }

    /// EVERY TRUST KEY and its state (`GET /api/v1/admin/trust`; [`TrustBook::rows`]).
    #[must_use]
    pub fn trust_rows(&self) -> Vec<KeyRow> {
        self.trust.rows()
    }

    /// THE OPERATOR'S DECISION about the trust key `key`, `<instance>/<counterparty>[/<item>]`
    /// (`POST /api/v1/admin/trust/approve` and `/revoke`; [`TrustBook::decide`]): matched against
    /// the keys [`Self::trust_rows`] lists, so a label or name holding a `/` is never split wrong.
    /// The decision is kept durably before it answers; approving a counterparty also clears its
    /// durable demotion. Idempotent.
    ///
    /// # Errors
    ///
    /// [`TrustRefused::NoSuchKey`] for a key no admitted instance has,
    /// [`TrustRefused::NothingSighted`] for an approval with nothing to approve at, and
    /// [`TrustRefused::Store`] (the store's words) when the decision could not be kept.
    pub fn trust_rule(&self, key: &str, ruling: Ruling) -> Result<KeyRow, TrustRefused> {
        let found = self
            .trust
            .rows()
            .into_iter()
            .find(|r| r.key() == key)
            .ok_or(TrustRefused::NoSuchKey)?;
        self.decide_key(
            &found.instance,
            &found.counterparty,
            found.item.as_deref(),
            ruling,
            None,
        )
    }

    /// THE ONE DECIDE PATH, the core-admin verbs' ([`Self::trust_rule`]) and a plane's own
    /// administrative verb's (`trust.decide`) alike: the trust book's decision
    /// ([`TrustBook::decide`]), kept durably before it answers; approving a counterparty also
    /// clears its durable demotion.
    ///
    /// # Errors
    ///
    /// The [`TrustRefused`] that refuses it.
    pub fn decide_key(
        &self,
        instance: &str,
        counterparty: &str,
        item: Option<&str>,
        ruling: Ruling,
        expected: Option<&str>,
    ) -> Result<KeyRow, TrustRefused> {
        let (row, fact) = self
            .trust
            .decide(instance, counterparty, item, ruling, expected)
            .map_err(|why| match why {
                Undecided::NoSuchKey => TrustRefused::NoSuchKey,
                Undecided::NothingSighted => TrustRefused::NothingSighted,
                Undecided::Rootless => TrustRefused::Rootless,
                Undecided::Stale => TrustRefused::Stale,
            })?;
        if let Some(d) = self.demotions.get() {
            d.record
                .keep_decision(&fact, (self.wall_ms)() / 1000)
                .map_err(TrustRefused::Store)?;
            if fact.item.is_none() && ruling == Ruling::Approve {
                let cleared = |server: &str| {
                    crate::plane::quarantine::settle(
                        &d.record,
                        server,
                        crate::trust::TrustState::Approved,
                    );
                };
                cleared(&demotion_key(&fact.instance, &fact.counterparty));
                if *d.default_instance == *fact.instance {
                    cleared(&fact.counterparty);
                }
            }
        }
        Ok(row)
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
        if target == busbar_contract::abi::host::service::ENTITLEMENT_STANDING {
            return self.stands(unit);
        }
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
        // THE PRINCIPAL AS IT STANDS NOW, re-resolved per ask where the root attached the live
        // resolution: one that no longer stands is entitled to nothing.
        let principal = match (record.principal.as_ref(), self.standing.get()) {
            (Some(admitted), Some(standing)) => match standing(admitted, now) {
                Some(live) => Some(live),
                None => return false,
            },
            (admitted, _) => admitted.cloned(),
        };
        validate_visibility(principal.as_deref(), now, &[Grant::Scope { kind, name }]).is_ok()
    }

    /// Whether `unit`'s principal still stands (an ungoverned unit, or one with no live
    /// resolution attached, stands as admitted).
    fn stands(&self, unit: Option<u64>) -> bool {
        let Some(record) = unit.and_then(|u| self.units.get(u)) else {
            return false;
        };
        match (record.principal.as_ref(), self.standing.get()) {
            (Some(admitted), Some(standing)) => {
                standing(admitted, (self.wall_ms)() / 1000).is_some()
            }
            _ => true,
        }
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
        if let Some(chain) = self.chained(caller, kind) {
            // A CHAINED KIND: appended to its journal on the pool, durable before `acked` hears
            // so; never put through the write-behind (a put keyed by scope would overwrite).
            let store = Arc::clone(&records.plane);
            let instance = Arc::clone(&caller.instance);
            let (key, content) = (key.to_vec(), value.as_slice().to_vec());
            pool.run(Box::new(move || {
                acked(chain.append(&store, &instance, &key, content));
            }));
            return Ok(());
        }
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

    /// The chained kind `kind` of the caller, when its tail declares that kind chained.
    fn chained(&self, caller: &Caller, kind: &str) -> Option<Arc<crate::host_chains::ChainedKind>> {
        self.chains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(Arc::clone(&caller.instance), kind.to_string()))
            .cloned()
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
        let (Some(records), Some(pool)) = (self.records.get(), self.pool()) else {
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

    /// The kernel's flush tick, run by [`Self::flushes`] every [`crate::host_records::FLUSH_INTERVAL`]:
    /// start a flush of the queued record writes when none runs, so writes a refused flush left
    /// queued still reach the store.
    pub fn flush_tick(&self) {
        if let (Some(records), Some(pool)) = (self.records.get(), self.pool()) {
            if self.batcher.start() {
                self.start_flush(records, pool);
            }
        }
    }

    /// THE WRITE-BEHIND CADENCE, for the services' life (ruling H2 U10: a tick of at most 1 s):
    /// [`Self::flush_tick`] every [`crate::host_records::FLUSH_INTERVAL`], the first one interval
    /// after it starts, whatever any plane's own tick schedule is. A record write whose flush the
    /// pool refused, with no later write to start another, reaches the store within one interval.
    /// The composition root runs it once, beside the services it built; it never ends.
    pub async fn flushes(&self) {
        let every = crate::host_records::FLUSH_INTERVAL;
        let mut at = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        at.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            at.tick().await;
            self.flush_tick();
            self.verify_tick();
        }
    }

    /// The verify cache's tick, run beside [`Self::flush_tick`]: every lead that lapsed passes to
    /// its first follower, so a leader that never stores wedges nobody past one interval.
    pub fn verify_tick(&self) {
        self.verify.expire((self.wall_ms)());
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
            .get()
            .ok_or_else(|| Stored::refused(NO_STORE))?;
        let pool = self.pool().ok_or_else(|| Stored::refused(NO_POOL))?;
        Ok((schema, records, pool))
    }
}

impl KernelServices {
    /// The owner digest of the principal of `unit`, while it is in flight.
    fn owner_of_unit(&self, unit: Option<u64>) -> Option<Owner> {
        let record = self.units.get(unit?)?;
        Some(owner_of(record.principal.as_deref().map(|k| k.id.as_str())))
    }

    /// The stores and pool a work call reaches, for an admitted caller; or the refusal.
    fn work_scope(
        &self,
        caller: &Caller,
    ) -> Result<(Arc<InstanceFacts>, &Records, &dyn Offload), Stored> {
        let facts = self
            .facts(caller)
            .ok_or_else(|| Stored::refused(NOT_ADMITTED))?;
        let records = self
            .records
            .get()
            .ok_or_else(|| Stored::refused(NO_STORE))?;
        let pool = self.pool().ok_or_else(|| Stored::refused(NO_POOL))?;
        Ok((facts, records, pool))
    }
}

/// A work handle's answer: `value` = the handle, span `0` = the state byte and the record.
fn work_found(handle: u64, w: &Work) -> Stored {
    let mut s = spans_of(vec![(vec![w.state()], w.record.clone())]);
    s.value = handle;
    s
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
/// The refusal of `trust.verify` for a counterparty whose declared pin names no root key.
pub const NO_ROOT_KEY: &str = "the counterparty declares no root key";
/// The refusal of `trust.verify` for signatures that are not one JSON document.
pub const SIGNATURES_NOT_JSON: &str = "the signatures are not one JSON document";
/// The refusal of a store-reaching service on a host with no pool bound.
pub const NO_POOL: &str = "no pool is bound";
/// The FAILED answer of a store call the pool refused to run.
pub const POOL_REFUSED: &str = "the pool refused the store call";
/// The FAILED answer of a store call that did not answer.
pub const STORE_FAILED: &str = "the store did not answer";
/// The FAILED answer of a `trust.decide` whose decision the store could not keep.
pub const DECISION_UNKEPT: &str = "the trust decision could not be kept";
/// The refusal of a `records.secret` read by services that hold no credential source (the root
/// composes the credential source over these services).
pub const NO_CREDENTIAL_SOURCE: &str = "no credential source";
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

/// Why an operator's trust decision was not made ([`KernelServices::trust_decide`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustRefused {
    /// No admitted instance has the key.
    NoSuchKey,
    /// The key was never sighted (nor declared) at anything to approve.
    NothingSighted,
    /// The counterparty declares no authenticity root: nothing at it can be approved.
    Rootless,
    /// The fingerprint the caller approves is not the key's current sighting.
    Stale,
    /// The decision could not be kept; the store's words, for the node's log.
    Store(String),
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
    let digest = busbar_kernel_ledger::digest::sha256_of(&[
        instance.as_bytes(),
        &[0],
        kind.as_bytes(),
        &[0],
        key,
    ]);
    let minted = IdempotencyKey::mint(&KernelSeal::acquire_for_kernel(), digest);
    hex::encode(minted.bytes())
}

impl HostServices for KernelServices {
    fn now(&self) -> Reading {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        Reading {
            wall_ns: wall,
            mono_ns: self.mono_ns.as_ref().map_or_else(
                || u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX),
                |mono| mono(),
            ),
        }
    }

    fn dest_judge(&self, dest: &str, class: u32, flags: u32, later: Option<Later>) -> Ran {
        let resolve = flags & svc::DEST_RESOLVE != 0;
        let refuse_private = flags & svc::DEST_REFUSE_PRIVATE != 0;
        let explain = flags & svc::DEST_EXPLAIN != 0;
        // The name and scheme arms first, at once: a refusal never waits on a resolution.
        let Some(j) = &self.judge else {
            return Ran::Now(Stored::refused(NO_DEST_JUDGE));
        };
        let named = j.judge_name(dest, class, refuse_private);
        match named {
            Err(v) => return Ran::Now(Stored::ready(v)),
            Ok(()) if resolve => {}
            Ok(()) => return Ran::Now(Stored::ready(svc::DEST_ALLOWED)),
        }
        let Some(later) = later else {
            return Ran::Now(Stored::refused(
                "a service that may pend is callable only inside a ticketed op",
            ));
        };
        // The one judge; the verdict is its answer, and admitted, every address it judged.
        let judgement = move |v| judged(v, explain);
        match j.judge(
            dest,
            class,
            refuse_private,
            Box::new(move |v| later(judgement(v))),
        ) {
            Some(v) => Ran::Now(judged(v, explain)),
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

    fn records_secret(&self, _kind: &str, _id: &str, _later: Later) -> Ran {
        Ran::Now(Stored::refused(NO_CREDENTIAL_SOURCE))
    }

    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran {
        match self.disk.submit(dest.clone(), bytes, later) {
            Ok(()) => Ran::Later,
            Err(report) => Ran::Now(report.stored()),
        }
    }

    fn session_emit(&self, caller: &Caller, session: u64, bytes: &[u8]) -> Stored {
        let open = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&session)
            .filter(|s| *s.instance == *caller.instance)
            .map(|s| (Arc::clone(&s.sink), s.principal.clone()));
        let Some((sink, principal)) = open else {
            return Stored::refused(SESSION_NOT_OPEN);
        };
        if !sink(bytes) {
            self.close_carrier_session(session);
            return Stored::refused(SESSION_NOT_OPEN);
        }
        // AUDITED AS A SESSION EVENT, under the session's verified principal: the write is the
        // instance's, unsolicited, and nothing bills it.
        crate::audit::auditlog::emit_admin_hostless_now(
            SESSION_EMIT_ACTION,
            &format!("session:{session}"),
            busbar_contract::vocab::OUTCOME_APPLIED,
            &principal,
        );
        Stored::ready(0)
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

    fn trust_unreached(&self, caller: &Caller, counterparty: &str) -> Stored {
        match self.trust.last_verdict(&caller.instance, counterparty) {
            Ok(sight) => Stored::ready(sight_code(sight)),
            Err(Unjudged::UnknownInstance) => Stored::refused(NOT_ADMITTED),
            Err(Unjudged::UnknownCounterparty) => Stored::refused(NOT_A_COUNTERPARTY),
        }
    }

    fn trust_decide(
        &self,
        caller: &Caller,
        key: busbar_contract::services::TrustKeyRef<'_>,
        expected: Option<&str>,
        approve: bool,
    ) -> Stored {
        if self.facts(caller).is_none() {
            return Stored::refused(NOT_ADMITTED);
        }
        let ruling = if approve {
            Ruling::Approve
        } else {
            Ruling::Revoke
        };
        Stored::ready(
            match self.decide_key(
                &caller.instance,
                key.counterparty,
                key.item,
                ruling,
                expected,
            ) {
                Ok(row) => decided_code(row.state),
                Err(TrustRefused::NoSuchKey) => svc::UNDECIDED_UNKNOWN,
                Err(TrustRefused::NothingSighted) => svc::UNDECIDED_UNPINNED,
                Err(TrustRefused::Stale) => svc::UNDECIDED_STALE,
                Err(TrustRefused::Rootless) => svc::UNDECIDED_ROOTLESS,
                Err(TrustRefused::Store(_)) => return failed(DECISION_UNKEPT),
            },
        )
    }

    fn trust_state(&self, caller: &Caller, counterparty: &str) -> Stored {
        let rows: Vec<KeyRow> = self
            .trust
            .rows()
            .into_iter()
            .filter(|r| *r.instance == *caller.instance && r.counterparty == counterparty)
            .collect();
        let Some(whole) = rows.iter().find(|r| r.item.is_none()) else {
            return Stored::refused(if self.facts(caller).is_some() {
                NOT_A_COUNTERPARTY
            } else {
                NOT_ADMITTED
            });
        };
        let mut stored = Stored::ready(key_code(whole.state));
        let cap = usize::try_from(MAX_SPANS).unwrap_or(usize::MAX);
        for row in rows.iter().filter(|r| r.item.is_some()).take(cap) {
            let item = row.item.as_deref().unwrap_or_default();
            let value = format!(
                "{}\0{}\0{}",
                row.state.word(),
                row.approved.as_deref().unwrap_or_default(),
                row.seen.as_deref().unwrap_or_default()
            );
            let off = stored.bytes.len();
            stored.bytes.extend_from_slice(item.as_bytes());
            stored.bytes.extend_from_slice(value.as_bytes());
            stored
                .spans
                .push(span(off, item.len(), off + item.len(), value.len()));
        }
        stored
    }

    fn trust_sight_item(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: &str,
        digest: &str,
    ) -> Stored {
        match self
            .trust
            .sight_item(&caller.instance, counterparty, item, digest)
        {
            Ok(sight) => Stored::ready(sight_code(sight)),
            Err(Unjudged::UnknownInstance) => Stored::refused(NOT_ADMITTED),
            Err(Unjudged::UnknownCounterparty) => Stored::refused(NOT_A_COUNTERPARTY),
        }
    }

    fn trust_serves(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: Option<&str>,
        digest: Option<&str>,
    ) -> Stored {
        let facts = TrustFacts {
            counterparty,
            item,
            digest,
        };
        Stored::ready(match self.trust.judge(&caller.instance, &facts) {
            Ok(()) => svc::DISTRUST_NONE,
            Err(why) => distrust_code(why),
        })
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

    fn trust_verify(&self, caller: &Caller, cp: &str, payload: &[u8], sigs: &[u8]) -> Stored {
        let key = match self.trust.root_key(&caller.instance, cp) {
            Ok(Some(key)) => key,
            Ok(None) => return Stored::refused(NO_ROOT_KEY),
            Err(Unjudged::UnknownInstance) => return Stored::refused(NOT_ADMITTED),
            Err(Unjudged::UnknownCounterparty) => return Stored::refused(NOT_A_COUNTERPARTY),
        };
        let sigs = match sigs {
            [] => serde_json::Value::Null,
            json => match serde_json::from_slice(json) {
                Ok(v) => v,
                Err(_) => return Stored::refused(SIGNATURES_NOT_JSON),
            },
        };
        let judged = signed::root_key(&key).and_then(|root| signed::verify(payload, &sigs, &root));
        let (value, named) = judged
            .err()
            .unwrap_or((svc::SIGNED_VERIFIED, String::new()));
        Stored {
            bytes: named.into_bytes(),
            ..Stored::ready(value)
        }
    }

    fn unit_nest(&self, caller: &Caller, unit: Option<u64>, ask: NestAsk, later: Later) -> Ran {
        if self.facts(caller).is_none() {
            return Ran::Now(Stored::refused(NOT_ADMITTED));
        }
        // THE PARENT: the unit the calling crossing serves, while it is in flight. Its record is
        // the child's principal and the depth the cap reads.
        let Some((parent, record)) = unit.and_then(|u| Some((u, self.units.get(u)?))) else {
            return Ran::Now(Stored::refused(NEST_NO_UNIT));
        };
        let Some(route) = self.nest.get() else {
            return Ran::Now(Stored::refused(NO_NEST_ROUTE));
        };
        let depth = record.depth.saturating_add(1);
        let permit = match self.nested.enter(depth as usize) {
            Ok(p) => p,
            Err(busbar_contract::caps::ReasonCode::InFlightCap) => {
                return Ran::Now(Stored::refused(NEST_FULL))
            }
            Err(_) => return Ran::Now(Stored::refused(NEST_TOO_DEEP)),
        };
        let owed = OwedNest {
            later: Some(later),
            pool: Arc::clone(&self.nested),
            permit: Some(permit),
        };
        route.nest(
            Nest {
                parent,
                depth,
                principal: record.principal.clone(),
                ask,
            },
            Box::new(move |reply| owed.answer(reply)),
        );
        Ran::Later
    }

    fn work_open(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        kind: &str,
        record: &[u8],
        later: Later,
    ) -> Ran {
        let (facts, records, pool) = match self.work_scope(caller) {
            Ok(s) => s,
            Err(refused) => return Ran::Now(refused),
        };
        if !facts.record_kinds.iter().any(|k| k.as_str() == kind) {
            return Ran::Now(Stored::refused(NOT_A_KIND));
        }
        if record.len() > svc::MAX_WORK_RECORD {
            return Ran::Now(Stored::refused(work_refusal::TOO_LONG));
        }
        let Some(owner) = self.owner_of_unit(unit) else {
            return Ran::Now(Stored::refused(work_refusal::NO_UNIT));
        };
        let book = Arc::clone(&self.work);
        let rows = Arc::clone(&records.reads);
        let bounds = self.work_bounds_of(&caller.instance);
        let wall_ms = Arc::clone(&self.wall_ms);
        let instance = Arc::clone(&caller.instance);
        let (kind, record) = (kind.to_string(), record.to_vec());
        submit(pool, later, move || {
            if book.load(&*rows, &instance).is_err() {
                return failed(STORE_FAILED);
            }
            let now_ms = wall_ms();
            // THE SWEEP RUNS ON SUBMIT: settled handles past their retention leave the book, and
            // their rows are struck (an empty row is absent).
            for gone in book.sweep(&instance, now_ms, bounds.retain_ms) {
                if let Ok(empty) = RecordBytes::new(Vec::new()) {
                    let _struck = rows.record_put(WORK_SCHEMA, &work_key(&instance, &gone), &empty);
                }
            }
            let mut reference = [0u8; 16];
            if getrandom::fill(&mut reference).is_err() {
                return failed(NO_RANDOMNESS);
            }
            let work = Work {
                instance: Arc::clone(&instance),
                reference,
                kind,
                owner,
                live: true,
                opened_ms: now_ms,
                settled_ms: 0,
                record,
                bound: None,
            };
            let Some(row) = work.row() else {
                return Stored::refused(work_refusal::TOO_LONG);
            };
            // THE BOUND REFUSES AT ADMISSION: the reservation is the bound's; nothing is evicted.
            let Some(handle) = book.reserve(work, bounds.max_live) else {
                return Stored::refused(work_refusal::AT_BOUND);
            };
            // Durable before answered: a write the store refuses leaves the book as it was.
            if rows
                .record_put(WORK_SCHEMA, &work_key(&instance, &reference), &row)
                .is_err()
            {
                book.unreserve(handle);
                return failed(STORE_FAILED);
            }
            let text = reference_text(&reference).into_bytes();
            let len = text.len();
            let mut s = Stored::ready(handle);
            s.bytes = text;
            s.spans.push(ItemSpan {
                value: absent_span(),
                ..span(0, len, 0, 0)
            });
            s
        })
    }

    fn work_find(&self, caller: &Caller, unit: Option<u64>, reference: &[u8], later: Later) -> Ran {
        let (_, records, pool) = match self.work_scope(caller) {
            Ok(s) => s,
            Err(refused) => return Ran::Now(refused),
        };
        let Some(owner) = self.owner_of_unit(unit) else {
            return Ran::Now(Stored::refused(work_refusal::NO_UNIT));
        };
        // EVERY DENIAL ANSWERS ALIKE: a malformed reference, an unknown one, another instance's,
        // another principal's, and one settled past its retention are each READY absent.
        let absent = || Stored::ready(svc::ABSENT);
        let Some(reference) = parse_reference(reference) else {
            return Ran::Now(absent());
        };
        let book = Arc::clone(&self.work);
        let rows = Arc::clone(&records.reads);
        let retain_ms = self.work_bounds_of(&caller.instance).retain_ms;
        let wall_ms = Arc::clone(&self.wall_ms);
        let instance = Arc::clone(&caller.instance);
        submit(pool, later, move || {
            let held = match book.by_reference(&instance, &reference) {
                Some(held) => Some(held),
                // Not in this process's book: the store's row (an earlier process's handle, or
                // another node's), adopted under a handle of this process's.
                None => match rows.record_get(WORK_SCHEMA, &work_key(&instance, &reference)) {
                    Err(_) => return failed(STORE_FAILED),
                    Ok(row) => row
                        .and_then(|row| Work::read(&instance, reference, row.as_slice()))
                        .map(|w| (book.adopt(w.clone()), w)),
                },
            };
            match held {
                Some((handle, w))
                    if w.owner == owner
                        && (w.live || w.settled_ms.saturating_add(retain_ms) > wall_ms()) =>
                {
                    work_found(handle, &w)
                }
                _ => absent(),
            }
        })
    }

    fn work_settle(&self, caller: &Caller, handle: u64, record: &[u8], later: Later) -> Ran {
        let (_, records, pool) = match self.work_scope(caller) {
            Ok(s) => s,
            Err(refused) => return Ran::Now(refused),
        };
        if record.len() > svc::MAX_WORK_RECORD {
            return Ran::Now(Stored::refused(work_refusal::TOO_LONG));
        }
        let now_ms = (self.wall_ms)();
        let (before, settled) =
            match self
                .work
                .settle(&caller.instance, handle, record.to_vec(), now_ms)
            {
                Ok(v) => v,
                Err(why) => return Ran::Now(Stored::refused(why)),
            };
        let Some(row) = settled.row() else {
            self.work.restore(handle, before);
            return Ran::Now(Stored::refused(work_refusal::TOO_LONG));
        };
        let book = Arc::clone(&self.work);
        let rows = Arc::clone(&records.reads);
        let key = work_key(&caller.instance, &settled.reference);
        submit(pool, later, move || {
            if rows.record_put(WORK_SCHEMA, &key, &row).is_err() {
                book.restore(handle, before);
                return failed(STORE_FAILED);
            }
            Stored::ready(0)
        })
    }

    fn work_resume(&self, caller: &Caller, unit: Option<u64>, handle: u64, _later: Later) -> Ran {
        if self.facts(caller).is_none() {
            return Ran::Now(Stored::refused(NOT_ADMITTED));
        }
        let (Some(unit), Some(owner)) = (unit, self.owner_of_unit(unit)) else {
            return Ran::Now(Stored::refused(work_refusal::NO_UNIT));
        };
        Ran::Now(
            match self.work.bind(&caller.instance, handle, &owner, unit) {
                Ok(w) => Stored {
                    value: 0,
                    ..work_found(handle, &w)
                },
                Err(why) => Stored::refused(why),
            },
        )
    }

    fn verify_lookup(&self, caller: &Caller, key: &[u8], later: Later) -> Ran {
        if self.facts(caller).is_none() {
            return Ran::Now(Stored::refused(NOT_ADMITTED));
        }
        self.verify
            .lookup(&caller.instance, key, (self.wall_ms)(), later)
    }

    fn verify_store(&self, caller: &Caller, key: &[u8], entry: &[u8], ttl_ms: u64) -> Stored {
        if self.facts(caller).is_none() {
            return Stored::refused(NOT_ADMITTED);
        }
        self.verify
            .store(&caller.instance, key, entry, ttl_ms, (self.wall_ms)())
    }

    fn content_scan(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        content: &[u8],
        later: Later,
    ) -> Ran {
        let stage = match self.stage_of(caller, unit) {
            Ok(stage) => stage,
            Err(refused) => return Ran::Now(refused),
        };
        stage.scan(
            content.to_vec(),
            Box::new(move |answer| {
                later(match answer {
                    StageAnswer::Pass => Stored::ready(svc::CONTENT_PASS),
                    StageAnswer::Stop { .. } => Stored::ready(svc::CONTENT_BLOCK),
                    // A gate never rewrites; a stage that could not run blocks nothing silently.
                    StageAnswer::Rewrote { .. } => failed(STAGE_ANSWERED_AMISS),
                    StageAnswer::Failed(why) => failed(why),
                });
            }),
        );
        Ran::Later
    }

    fn hook_call(&self, caller: &Caller, unit: Option<u64>, ask: HookAsk, later: Later) -> Ran {
        let stage = match self.stage_of(caller, unit) {
            Ok(stage) => stage,
            Err(refused) => return Ran::Now(refused),
        };
        stage.call(
            ask,
            Box::new(move |answer| {
                later(match answer {
                    StageAnswer::Pass => Stored::ready(0),
                    StageAnswer::Rewrote { index, rewrite } => Stored {
                        bytes: rewrite,
                        ..Stored::ready(1 + u64::from(index))
                    },
                    StageAnswer::Stop { status, words } => Stored {
                        bytes: words.into_bytes(),
                        ..Stored::ready(u64::from(status))
                    },
                    StageAnswer::Failed(why) => failed(why),
                });
            }),
        );
        Ran::Later
    }

    fn snapshot_read(&self, _caller: &Caller, scope: u32) -> busbar_contract::services::Snapshot {
        crate::export::scrape::read(scope)
    }
}

/// The refusal of `content.scan` / `hook.call` from a crossing that serves no unit in flight.
pub const STAGE_NO_UNIT: &str = "the crossing serves no unit in flight";
/// The refusal of `content.scan` / `hook.call` before the unit's route leg stated its hook stage.
pub const STAGE_NOT_BOUND: &str = "the unit's hook stage is not bound yet";
/// The refusal of `content.scan` / `hook.call` for a unit another instance runs.
pub const STAGE_NOT_YOURS: &str = "the unit runs on another instance";
/// The FAILED answer of a stage that answered outside its service's shape.
pub const STAGE_ANSWERED_AMISS: &str = "the hook stage answered outside the service's shape";

impl KernelServices {
    /// The hook stage of `unit` for `caller`: the unit in flight, its route leg's stage stated, and
    /// run on the caller's own instance; or the refusal.
    fn stage_of(
        &self,
        caller: &Caller,
        unit: Option<u64>,
    ) -> Result<Arc<dyn crate::host_units::UnitHookStage>, Stored> {
        if self.facts(caller).is_none() {
            return Err(Stored::refused(NOT_ADMITTED));
        }
        let Some(unit) = unit.filter(|u| self.units.get(*u).is_some()) else {
            return Err(Stored::refused(STAGE_NO_UNIT));
        };
        let stage = self
            .units
            .stage(unit)
            .ok_or_else(|| Stored::refused(STAGE_NOT_BOUND))?;
        if stage.instance() != &*caller.instance {
            return Err(Stored::refused(STAGE_NOT_YOURS));
        }
        Ok(stage)
    }
}

/// Where a dial's judgement goes when it pended: the pinned address, or the `DEST_*` verdict that
/// refused it. Called once, from any thread.
pub type Judged = Box<dyn FnOnce(Result<SocketAddr, u64>) + Send>;

/// THE ONE JUDGEMENT'S ANSWER: the pinned address and every address judged with it (the pin
/// first), or the [`Refused`] verdict refusing them.
pub type Admitted = Result<(SocketAddr, Vec<IpAddr>), Refused>;

/// `dest.judge`'s stored answer for a judgement: the verdict, and admitted, one span per judged
/// address (key = the address as text, value absent); refused and asked to `explain`, one span
/// naming what decided it, when an address or the resolution did.
fn judged(v: Admitted, explain: bool) -> Stored {
    let (mut s, keys) = match v {
        Ok((_, addrs)) => (
            Stored::ready(svc::DEST_ALLOWED),
            addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ),
        Err(r) => (
            Stored::ready(r.verdict),
            r.detail.filter(|_| explain).into_iter().collect(),
        ),
    };
    for key in keys {
        let at = s.bytes.len();
        s.bytes.extend_from_slice(key.as_bytes());
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
        let pin = |v: Admitted| v.map(|(addr, _)| addr).map_err(|r| r.verdict);
        match &self.judge {
            Some(j) => j
                .judge(dest, class, false, Box::new(move |v| done(pin(v))))
                .map(pin),
            None => Some(Err(svc::DEST_NO_HOST)),
        }
    }
}

/// An absent span.
const fn absent_span() -> Span {
    Span {
        offset: busbar_contract::abi::mechanism::check::SPAN_ABSENT,
        len: 0,
    }
}

#[cfg(test)]
#[path = "tests/host_services_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/trust_verify_tests.rs"]
mod trust_verify_tests;

#[cfg(test)]
#[path = "tests/host_nest_tests.rs"]
mod host_nest_tests;

/// The `TRUST_DECIDED_*` verdict (`trust.decide`) a key's [`KeyState`] is answered as.
#[must_use]
pub fn decided_code(state: KeyState) -> u64 {
    match state {
        KeyState::Same | KeyState::Approved => svc::TRUST_DECIDED_SERVING,
        KeyState::New => svc::TRUST_DECIDED_PENDING,
        KeyState::Drifted | KeyState::Quarantined => svc::TRUST_DECIDED_QUARANTINED,
    }
}

/// The `KEY_*` value (`trust.state`) a [`KeyState`] is answered as.
#[must_use]
pub fn key_code(state: KeyState) -> u64 {
    match state {
        KeyState::New => svc::KEY_NEW,
        KeyState::Same => svc::KEY_SAME,
        KeyState::Drifted => svc::KEY_DRIFTED,
        KeyState::Quarantined => svc::KEY_QUARANTINED,
        KeyState::Approved => svc::KEY_APPROVED,
    }
}

/// The `TRUST_*` sighting verdict a [`Sight`] is answered as.
#[must_use]
pub fn sight_code(sight: Sight) -> u64 {
    match sight {
        Sight::New => svc::TRUST_NEW,
        Sight::Same => svc::TRUST_SAME,
        Sight::Drifted => svc::TRUST_DRIFTED,
        Sight::Quarantined => svc::TRUST_QUARANTINED,
    }
}

/// The `DISTRUST_*` code (the one trust vocabulary: `trust.serves`'s value and a refused unit's
/// `RefusalIn::trust`) a [`Distrust`] is.
#[must_use]
pub fn distrust_code(why: Distrust) -> u64 {
    match why {
        Distrust::Unknown => svc::DISTRUST_UNKNOWN,
        Distrust::Unsighted => svc::DISTRUST_UNSIGHTED,
        Distrust::Quarantined => svc::DISTRUST_QUARANTINED,
        Distrust::NotApproved => svc::DISTRUST_NOT_APPROVED,
        Distrust::Changed => svc::DISTRUST_CHANGED,
        Distrust::UnknownItem => svc::DISTRUST_UNKNOWN_ITEM,
    }
}

#[cfg(test)]
#[path = "tests/host_stage_tests.rs"]
mod host_stage_tests;
