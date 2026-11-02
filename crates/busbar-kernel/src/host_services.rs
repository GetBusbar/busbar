// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use busbar_contract::abi::host::service::{self as svc, ItemSpan, MAX_SPANS};
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::caps::IdempotencyKey;
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{RecordStore, RecordStoreResult, Retention};
use busbar_contract::services::{
    merge_list, Caller, CredentialRead, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran,
    Reading, RecordsList, Stored,
};

pub const QUEUE_FULL: &str = "the record write queue is full";

use crate::host_records::{
    record_key, Acked, Owed as WriteOwed, PendingRecords, RecordRows, Write, WriteBehind,
};
use crate::host_units::StageAnswer;
use crate::host_work::{
    owner_of, parse_reference, reference_text, refusal as work_refusal, work_key, Owner, Work,
    WorkBook, WorkBounds, WORK_SCHEMA,
};
use crate::trust::book::{
    Distrust, Effect, KeyRow, KeyState, Ruling, Sight, TrustBook, TrustFacts, Undecided, Unjudged,
};
use crate::trust::demotion::DemotionRecord;
use crate::trust::section::TrustEntry;
use crate::trust::signed;

pub trait DestJudge: Send + Sync {
    fn judge_name(&self, dest: &str, class: u32, refuse_private: bool) -> Result<(), u64>;

    fn judge(
        &self,
        dest: &str,
        class: u32,
        refuse_private: bool,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted>;

    fn judge_reaching(
        &self,
        dest: &str,
        class: u32,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        self.judge(dest, class, false, done)
    }

    fn judge_answer(&self, host: &str, addrs: &[IpAddr], class: u32) -> Result<(), DestRefusal>;

    fn judge_host(&self, host: &str, class: u32) -> Result<(), DestRefusal> {
        self.judge_name(host, class, false)
            .map_err(|verdict| DestRefusal {
                verdict,
                reason: format!("host `{host}` was refused by the destination guard"),
            })
    }

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

pub trait NestRoute: Send + Sync {
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
    /// The child already ran, but its reply could not be read; FAILED with this reason.
    Failed(&'static str),
}

pub type NestDone = Box<dyn FnOnce(NestReply) + Send>;

pub const NEST_DEPTH_MAX: u32 = 3;

pub const NEST_CONCURRENCY: usize = 256;

pub const NEST_NO_UNIT: &str = "the crossing serves no unit in flight";

pub const NEST_TOO_DEEP: &str = "the nested unit would be deeper than the nesting cap";

pub const NEST_FULL: &str = "the node runs as many nested units as it holds";

pub const NO_NEST_ROUTE: &str = "no nested dispatch is installed";

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

pub const NO_DEST_JUDGE: &str = "no destination judge is installed";

pub trait Offload: Send + Sync {
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
    #[must_use]
    pub fn new(handle: tokio::runtime::Handle, bound: usize) -> Self {
        Self {
            handle,
            held: Arc::default(),
            bound,
        }
    }
}

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

            return;
        }
        let place = Place(Arc::clone(&self.held));

        drop(self.handle.spawn_blocking(move || {
            let _place = place;
            job();
        }));
    }
}

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

struct TrustSightOwed {
    permit: Option<crate::trust::book::DecisionPermit>,
    later: Option<Later>,
}

impl TrustSightOwed {
    fn answer(mut self, answer: Stored) {
        drop(self.permit.take());
        if let Some(later) = self.later.take() {
            later(answer);
        }
    }
}

impl Drop for TrustSightOwed {
    fn drop(&mut self) {
        drop(self.permit.take());
        if let Some(later) = self.later.take() {
            later(failed(POOL_REFUSED));
        }
    }
}

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

fn nested_answer(reply: NestReply) -> Stored {
    let (status, fields, body) = match reply {
        NestReply::Answered {
            status,
            fields,
            body,
        } => (status, fields, body),
        NestReply::Unserved(why) => return Stored::refused(why),
        NestReply::Failed(why) => return failed(why),
    };
    let mut s = Stored::ready(u64::from(status));
    let len = body.len();
    s.bytes = body;
    s.spans.push(ItemSpan {
        key: absent_span(),
        ..span(0, 0, 0, len)
    });

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

struct Unwritten {
    book: Arc<WorkBook>,
    handle: u64,
    settled: Option<Work>,
    later: Option<Later>,
}

impl Unwritten {
    fn answer(mut self, confirmed: bool) {
        if let Some(settled) = self.settled.take() {
            if confirmed {
                self.book.commit_settle(self.handle, settled);
            } else {
                self.book.cancel_settle(self.handle);
            }
        }
        if let Some(later) = self.later.take() {
            later(if confirmed {
                Stored::ready(0)
            } else {
                failed(STORE_FAILED)
            });
        }
    }
}

impl Drop for Unwritten {
    fn drop(&mut self) {
        if self.settled.take().is_some() {
            self.book.cancel_settle(self.handle);
        }
        if let Some(later) = self.later.take() {
            later(failed(POOL_REFUSED));
        }
    }
}

struct LifeObservationOwed(Option<crate::host_records::ChainLifeAcked>);

impl LifeObservationOwed {
    fn answer(
        mut self,
        result: Result<busbar_contract::abi::sdk::store::conditional::Expected, &'static str>,
    ) {
        if let Some(done) = self.0.take() {
            done(result);
        }
    }
}

impl Drop for LifeObservationOwed {
    fn drop(&mut self) {
        if let Some(done) = self.0.take() {
            done(Err("chain life observation was not run"));
        }
    }
}

fn submit(pool: &dyn Offload, later: Later, job: impl FnOnce() -> Stored + Send + 'static) -> Ran {
    let owed = Owed(Some(later));
    pool.run(Box::new(move || owed.answer(job())));
    Ran::Later
}

pub trait SignKey: Send + Sync {
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
    /// Declared kind indices requiring conditional publication, established before admission.
    /// Ordinary record writes must never share these namespaces with conditional candidates.
    pub conditional_record_kinds: Vec<u32>,
    /// Its signing declaration; `None` = `sign` is refused.
    pub signing: Option<Signing>,
    /// Its trust entries, one per counterparty, as `trust::section` parsed them.
    pub trust: Vec<(String, TrustEntry)>,
    /// The scope kinds its tail declares: `entitlement.check` answers only for these.
    pub scope_kinds: Vec<String>,
    /// Its chained record kinds, as its tail declares them (`PlaneTail::record_chains`, each `kind`
    /// an index into [`InstanceFacts::record_kinds`]): a record write of one is APPENDED to its
    /// chain, framed and sealed by the host and verified when read (`crate::host_chains`), never
    /// put.
    pub record_chains: Vec<busbar_contract::abi::plane::RecordChain>,
    /// Its record kinds' retention rules, as its tail declares them
    /// (`PlaneTail::record_retentions`, each `kind` an index into [`InstanceFacts::record_kinds`]):
    /// every purge of a listed kind passes its rule ([`KernelServices::record_retention`]); every
    /// other kind is purged by age.
    pub record_retentions: Vec<busbar_contract::abi::plane::RecordRetention>,
    /// The issued-id prefix its Statement declares (`MARK_WORD_ISSUED_ID_PREFIX`): what leads every
    /// ticket minted for it. `None` = it mints no ticket, and `ticket.mint` is refused.
    pub ticket_prefix: Option<String>,
}

pub trait TicketPress: Send + Sync {
    fn mint(
        &self,
        key_id: &str,
        prefix: &str,
        ttl_secs: u64,
        record: &[u8],
        now: u64,
    ) -> Result<(String, u64), &'static str>;
}

pub const TICKET_NO_PRINCIPAL: &str = "no ticket is minted outside a unit with a principal";

pub const TICKET_NO_PREFIX: &str = "no ticket is minted for an instance that declares no prefix";

pub const TICKET_NO_PRESS: &str = "this host mints no tickets";

pub const TICKET_NOT_HELD: &str = "no ticket record is held for this unit";

pub const RESERVED_RECORD_KINDS: &[&str] = &[
    crate::governance::TICKET_RECORD_KIND,
    crate::host_work::WORK_SCHEMA.as_str(),
    crate::host_chains::CHAIN_LIFE_SCHEMA.as_str(),
];

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
    /// A declared chained record kind this host cannot chain: its kind index names no record kind,
    /// or its framing is a word this host does not know. A record kind declared chained is
    /// chained, never silently kept as plain records.
    ChainUnknown {
        /// The declaration's kind index.
        kind: u32,
        /// The declaration's framing word.
        framing: u32,
    },
    /// A conditional kind index is undeclared or repeated.
    ConditionalKind {
        /// The invalid declared-kind index.
        kind: u32,
    },
    /// The store could not be read for the demotions and the operator's trust decisions this
    /// instance's trust stands on.
    TrustUnread(String),
    /// The instance declares a record kind the kernel keeps its own records under
    /// ([`RESERVED_RECORD_KINDS`]): its retention rule would govern the kernel's own rows.
    KindReserved {
        /// The instance refused.
        instance: String,
        /// The reserved kind it declares.
        kind: String,
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
            Self::ChainUnknown { kind, framing } => write!(
                f,
                "the instance declares chained record kind {kind} with framing {framing}, which \
                 this host cannot chain: a declared chain is kept, never dropped to plain records"
            ),
            Self::ConditionalKind { kind } => write!(f, "invalid conditional record kind {kind}"),
            Self::TrustUnread(why) => write!(
                f,
                "{why}; the instance is not admitted over trust it cannot read"
            ),
            Self::KindReserved { instance, kind } => write!(
                f,
                "instance `{instance}` declares the record kind `{kind}`, which the kernel keeps \
                 its own records under: no instance keeps records under a kernel kind, so the \
                 instance is not admitted"
            ),
        }
    }
}

impl std::error::Error for AdmitRefused {}

fn trust_unread(why: String) -> AdmitRefused {
    crate::diagnostics::diag_error!(
        crate::diagnostics::PLANE_DEMOTIONS_UNREAD,
        error = %why,
        "the durable trust records could NOT be read: the plane instance is refused rather than \
         re-open a demoted upstream or stand over an operator's revoke"
    );
    AdmitRefused::TrustUnread(why)
}

struct Records {
    reads: Arc<dyn RecordRows>,
}

pub type WallMs = Arc<dyn Fn() -> u64 + Send + Sync>;

pub type MonoNs = Arc<dyn Fn() -> u64 + Send + Sync>;

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

pub struct KernelServices {
    origin: Instant,
    wall_ms: WallMs,

    mono_ns: Option<MonoNs>,
    instances: Mutex<HashMap<Arc<str>, Arc<InstanceFacts>>>,
    plane_cleanup: Mutex<Vec<std::sync::Weak<crate::plane_driver::PlaneDriver>>>,
    records: OnceLock<Records>,
    pool: OnceLock<Arc<dyn Offload>>,
    pending: Arc<PendingRecords>,
    units: Arc<crate::host_units::UnitRecords>,
    batcher: Arc<WriteBehind>,

    chains: Arc<crate::host_chains::ChainBook>,
    signer: OnceLock<Arc<dyn SignKey>>,
    trust: Arc<TrustBook>,

    trust_resync: Arc<(std::sync::atomic::AtomicU64, std::sync::atomic::AtomicBool)>,

    judge: Option<Arc<dyn DestJudge>>,
    demotions: OnceLock<Demotions>,

    work: Arc<WorkBook>,
    work_bounds: WorkBounds,

    bounds_of: Mutex<HashMap<Arc<str>, WorkBounds>>,

    nest: OnceLock<Arc<dyn NestRoute>>,

    standing: OnceLock<Standing>,
    nested: Arc<crate::pump::NestedPool>,

    disk: Arc<crate::host_disk::DiskLane>,

    sessions: Mutex<HashMap<u64, CarrierSession>>,

    verify: crate::host_verify::VerifyBook,

    credentials: Option<Arc<dyn CredentialRead>>,

    tickets: OnceLock<Arc<dyn TicketPress>>,
}

struct CarrierSession {
    instance: Arc<str>,

    principal: String,

    sink: CarrierSink,
}

pub type CarrierSink = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

pub const SESSION_EMIT_ACTION: &str = "session.emit";

pub const SESSION_NOT_OPEN: &str = "no such carrier session is open for this instance";

struct Demotions {
    record: Arc<DemotionRecord>,
    default_instance: Arc<str>,
}

struct TrustResync(Arc<(std::sync::atomic::AtomicU64, std::sync::atomic::AtomicBool)>);

impl Drop for TrustResync {
    fn drop(&mut self) {
        let (_, running) = &*self.0;
        running.store(false, std::sync::atomic::Ordering::Release);
    }
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
            wall_ms: Arc::new(system_wall_ms),
            mono_ns: None,
            instances: Mutex::default(),
            plane_cleanup: Mutex::default(),
            records: OnceLock::new(),
            pool: OnceLock::new(),
            pending: Arc::default(),
            units: Arc::default(),
            batcher: Arc::default(),
            chains: Arc::default(),
            signer: OnceLock::new(),
            trust: Arc::default(),
            trust_resync: Arc::default(),
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
            disk: Arc::default(),
            sessions: Mutex::default(),
            verify: crate::host_verify::VerifyBook::default(),
            credentials: None,
            tickets: OnceLock::new(),
        }
    }

    pub fn attach_tickets(&self, press: Arc<dyn TicketPress>) -> bool {
        self.tickets.set(press).is_ok()
    }

    #[must_use]
    pub fn ticket_prefix_of(&self, instance: &str) -> Option<String> {
        self.lock_instances()
            .get(instance)
            .and_then(|f| f.ticket_prefix.clone())
    }

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

    pub fn close_carrier_session(&self, session: u64) {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&session);
    }

    pub fn attach_nest(&self, route: Arc<dyn NestRoute>) -> bool {
        self.nest.set(route).is_ok()
    }

    pub fn attach_standing(&self, standing: Standing) -> bool {
        self.standing.set(standing).is_ok()
    }

    #[must_use]
    pub fn nested(&self) -> &Arc<crate::pump::NestedPool> {
        &self.nested
    }

    #[must_use]
    pub fn with_work_bounds(mut self, bounds: WorkBounds) -> Self {
        self.work_bounds = bounds;
        self
    }

    #[must_use]
    pub fn work(&self) -> &Arc<WorkBook> {
        &self.work
    }

    #[must_use]
    pub fn default_work_bounds(&self) -> WorkBounds {
        self.work_bounds
    }

    pub fn bound_work(&self, instance: &str, bounds: WorkBounds) {
        self.bounds_of
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(Arc::from(instance), bounds);
    }

    #[must_use]
    pub fn work_bounds_of(&self, instance: &str) -> WorkBounds {
        self.bounds_of
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(instance)
            .copied()
            .unwrap_or(self.work_bounds)
    }

    #[must_use]
    pub fn with_dest_judge(mut self, judge: Arc<dyn DestJudge>) -> Self {
        self.judge = Some(judge);
        self
    }

    #[must_use]
    pub fn with_credentials(mut self, credentials: Arc<dyn CredentialRead>) -> Self {
        self.credentials = Some(credentials);
        self
    }

    #[must_use]
    pub fn with_disk_lane(mut self, lane: Arc<crate::host_disk::DiskLane>) -> Self {
        self.disk = lane;
        self
    }

    #[must_use]
    pub fn with_records(self, reads: Arc<dyn RecordRows>) -> Self {
        self.attach_records(reads);
        self
    }

    pub fn attach_records(&self, reads: Arc<dyn RecordRows>) -> bool {
        self.records.set(Records { reads }).is_ok()
    }

    #[must_use]
    pub fn with_pool(mut self, pool: Arc<dyn Offload>) -> Self {
        self.pool = OnceLock::from(pool);
        self
    }

    #[must_use]
    pub fn with_signer(mut self, signer: Arc<dyn SignKey>) -> Self {
        self.signer = OnceLock::from(signer);
        self
    }

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

    pub fn attach_pool(&self, pool: Arc<dyn Offload>) -> bool {
        self.pool.set(pool).is_ok()
    }

    pub fn attach_signer(&self, signer: Arc<dyn SignKey>) -> bool {
        self.signer.set(signer).is_ok()
    }

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

    #[must_use]
    pub fn with_wall_clock(mut self, wall_ms: WallMs) -> Self {
        self.wall_ms = wall_ms;
        self
    }

    #[must_use]
    pub fn with_mono_clock(mut self, mono_ns: MonoNs) -> Self {
        self.mono_ns = Some(mono_ns);
        self
    }

    pub fn admit(&self, instance: &str, facts: InstanceFacts) -> Result<(), AdmitRefused> {
        if instance.len() > usize::from(u16::MAX) || instance.chars().any(char::is_control) {
            return Err(AdmitRefused::LabelUnfit {
                len: instance.len(),
            });
        }

        if let Some(kind) = facts
            .record_kinds
            .iter()
            .find(|k| RESERVED_RECORD_KINDS.contains(&k.as_str()))
        {
            crate::diagnostics::diag_error!(
                crate::diagnostics::PLANE_RECORD_KIND_RESERVED,
                instance = %instance,
                kind = %kind.as_str(),
                "a plane instance declares a record kind the kernel keeps its own records under: \
                 the instance is refused rather than write beside, or purge under its own rule, \
                 the kernel's records"
            );
            return Err(AdmitRefused::KindReserved {
                instance: instance.to_string(),
                kind: kind.as_str().to_string(),
            });
        }

        for chain in &facts.record_chains {
            let unknown = AdmitRefused::ChainUnknown {
                kind: chain.kind,
                framing: chain.framing,
            };
            if facts.record_kinds.get(chain.kind as usize).is_none()
                || crate::host_chains::ChainFraming::of(chain).is_none()
            {
                return Err(unknown);
            }
        }
        let mut conditional_kinds = std::collections::HashSet::new();
        for &kind in &facts.conditional_record_kinds {
            let Some(schema) = facts.record_kinds.get(kind as usize) else {
                return Err(AdmitRefused::ConditionalKind { kind });
            };
            if !conditional_kinds.insert(kind)
                || facts
                    .record_kinds
                    .iter()
                    .filter(|other| *other == schema)
                    .count()
                    != 1
            {
                return Err(AdmitRefused::ConditionalKind { kind });
            }
        }
        let key: Arc<str> = Arc::from(instance);

        let (rows, default) = match self.demotions.get() {
            Some(d) => (
                d.record.read().map_err(trust_unread)?,
                *d.default_instance == *instance,
            ),
            None => (Vec::new(), false),
        };

        let first = !self.lock_instances().contains_key(instance);
        let decided = match self.demotions.get() {
            Some(d) if first => d.record.decisions().map_err(trust_unread)?,
            _ => Vec::new(),
        };
        let mut instances = self.lock_instances();
        let decided = if instances.contains_key(instance) {
            Vec::new()
        } else {
            decided
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
            let counterparty = match r.upstream.strip_prefix(prefix.as_str()) {
                Some(cp) => cp,
                None if default && !r.upstream.contains(DEMOTION_SEP) => r.upstream.as_str(),
                None => return None,
            };
            Some((counterparty, r.recorded_at.saturating_mul(1000)))
        });
        self.trust
            .admit_with_decisions(&key, facts.trust.iter().cloned(), replayed, &decided);
        instances.insert(key, Arc::new(facts));
        Ok(())
    }

    pub fn trust_judge(&self, instance: &str, facts: &TrustFacts<'_>) -> Result<(), Distrust> {
        self.trust.judge(instance, facts)
    }

    #[must_use]
    pub fn trust_rows(&self) -> Vec<KeyRow> {
        self.trust.rows()
    }

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

    pub fn decide_key(
        &self,
        instance: &str,
        counterparty: &str,
        item: Option<&str>,
        ruling: Ruling,
        expected: Option<&str>,
    ) -> Result<KeyRow, TrustRefused> {
        let refused = |why: Undecided| match why {
            Undecided::NoSuchKey => TrustRefused::NoSuchKey,
            Undecided::NothingSighted => TrustRefused::NothingSighted,
            Undecided::Rootless => TrustRefused::Rootless,
            Undecided::Stale => TrustRefused::Stale,
            Undecided::Unverified => TrustRefused::Unverified,
        };

        let permit = self
            .trust
            .begin_decision(instance, counterparty, item)
            .map_err(refused)?;
        let fact = self
            .trust
            .rule(instance, counterparty, item, ruling, expected)
            .map_err(refused)?;
        if let Some(d) = self.demotions.get() {
            d.record
                .keep_decision(&fact, (self.wall_ms)() / 1000)
                .map_err(TrustRefused::Store)?;
        }
        let row = permit.apply(&fact).map_err(refused)?;
        let clears = fact.item.is_none() && ruling == Ruling::Approve;
        if let Some(d) = self.demotions.get().filter(|_| clears) {
            let cleared = |server: &str| {
                crate::trust::demotion::settle(
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
        Ok(row)
    }

    #[must_use]
    pub fn units(&self) -> &Arc<crate::host_units::UnitRecords> {
        &self.units
    }

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

        let principal = match (record.principal.as_ref(), self.standing.get()) {
            (Some(admitted), Some(standing)) => match standing(admitted, now) {
                Some(live) => Some(live),
                None => return false,
            },
            (admitted, _) => admitted.cloned(),
        };
        validate_visibility(principal.as_deref(), now, &[Grant::Scope { kind, name }]).is_ok()
    }

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

    #[must_use]
    pub fn pending(&self) -> &Arc<PendingRecords> {
        &self.pending
    }

    pub fn record_write(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        value: RecordBytes,
        acked: Acked,
    ) -> Result<(), &'static str> {
        let (schema, records, pool) = self.scope(caller, kind).map_err(|s| s.error)?;
        if self.conditional_kind(&caller.instance, kind) {
            return Err("this record kind requires conditional publication");
        }
        let chain = self.chain_of(caller, kind);
        if chain.is_some() {
            if crate::host_chains::scope_of(key).is_none() {
                return Err(crate::host_chains::CHAIN_SCOPE_UNFIT);
            }
            let room = busbar_contract::bounded::MAX_RECORD_BYTES
                .saturating_sub(crate::host_chains::CHAIN_OVERHEAD);
            if value.as_slice().len() > room {
                return Err(crate::host_chains::CHAIN_RECORD_TOO_LARGE);
            }
        }
        let pending = &self.pending;
        let started = self.batcher.push_with(|| {
            let seq = match chain {
                Some(_) => 0,
                None => pending.enqueue(&caller.instance, kind, key, value.as_slice().to_vec()),
            };
            Write {
                instance: Arc::clone(&caller.instance),
                schema,
                key: key.to_vec(),
                value,
                seq,
                owed: WriteOwed::new(acked),
                chain,
            }
        });
        match started {
            Some(true) => self.start_flush(records, pool),
            Some(false) => {}
            None => return Err(QUEUE_FULL),
        }
        Ok(())
    }

    fn conditional_kind(&self, instance: &str, kind: &str) -> bool {
        self.lock_instances().get(instance).is_some_and(|facts| {
            facts.conditional_record_kinds.iter().any(|index| {
                facts
                    .record_kinds
                    .get(*index as usize)
                    .is_some_and(|schema| schema.as_str() == kind)
            })
        })
    }

    #[must_use]
    pub fn supports_record_transactions(&self) -> bool {
        self.records
            .get()
            .is_some_and(|r| r.reads.supports_record_transaction())
    }

    pub fn observe_chain_life(
        &self,
        caller: &Caller,
        kind: u32,
        scope: &[u8],
        done: crate::host_records::ChainLifeAcked,
    ) -> Result<(), &'static str> {
        let facts = self.facts(caller).ok_or(NOT_A_KIND)?;
        if !facts.conditional_record_kinds.contains(&kind) {
            return Err("this record kind did not negotiate conditional publication");
        }
        let schema = facts
            .record_kinds
            .get(kind as usize)
            .copied()
            .ok_or(NOT_A_KIND)?;
        if !facts.record_chains.iter().any(|chain| chain.kind == kind) {
            return Err("life observation requires a declared chain");
        }
        let scope = crate::host_chains::scope_of(scope)
            .ok_or(crate::host_chains::CHAIN_SCOPE_UNFIT)?
            .to_string();
        let records = self.records.get().ok_or(NO_STORE)?;
        let pool = self.pool().ok_or(NO_POOL)?;
        if !records.reads.supports_record_transaction() {
            return Err("record transactions are unsupported");
        }
        let rows = Arc::clone(&records.reads);
        let instance = Arc::clone(&caller.instance);
        let owed = LifeObservationOwed(Some(done));
        pool.run(Box::new(move || {
            owed.answer(crate::host_chains::observe_life(
                &*rows, &instance, schema, &scope,
            ));
        }));
        Ok(())
    }

    pub fn record_transaction(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        candidate: crate::host_records::ConditionalCandidate,
        acked: crate::host_records::ConditionalAcked,
    ) -> Result<(), &'static str> {
        let candidate = zeroize::Zeroizing::new(candidate);
        use crate::host_records::{
            ChainMutation, ConditionalOwed, ConditionalWrite, RecordMutation,
        };
        use busbar_contract::abi::sdk::store::conditional::{
            Mutation, Predicate, Request, VERSION,
        };
        let facts = self.facts(caller).ok_or(NOT_A_KIND)?;
        let records = self.records.get().ok_or(NO_STORE)?;
        let pool = self.pool().ok_or(NO_POOL)?;
        if !records.reads.supports_record_transaction() {
            return Err("record transactions are unsupported");
        }
        let unit = unit
            .map(|id| self.units.get(id).ok_or("record transaction unit ended"))
            .transpose()?;
        let chain_at = |kind: u32| {
            facts
                .record_chains
                .iter()
                .find(|chain| chain.kind == kind)
                .and_then(crate::host_chains::ChainFraming::of)
        };
        let schema_at = |kind: u32, chained: bool| {
            if !facts.conditional_record_kinds.contains(&kind) {
                return Err("this record kind did not negotiate conditional publication");
            }
            let schema = facts
                .record_kinds
                .get(kind as usize)
                .copied()
                .ok_or(NOT_A_KIND)?;
            if chain_at(kind).is_some() != chained {
                return Err("record transaction kind has incompatible chain declaration");
            }
            Ok(schema)
        };
        let mut request = zeroize::Zeroizing::new(Request {
            version: VERSION,
            op_id: crate::door::op_id(),
            predicates: Vec::new(),
            mutations: Vec::new(),
        });
        for predicate in &candidate.predicates {
            let schema = schema_at(predicate.kind, false)?;
            request.predicates.reserve(1);
            request.predicates.push(Predicate {
                schema: schema.as_str().to_string(),
                key: record_key(&caller.instance, &predicate.key),
                expected: predicate.expected.clone(),
            });
        }
        for mutation in &candidate.mutations {
            request.mutations.reserve(1);
            request.mutations.push(match mutation {
                RecordMutation::Put { kind, key, value } => {
                    let schema = schema_at(*kind, false)?;
                    Mutation::Put {
                        schema: schema.as_str().to_string(),
                        key: record_key(&caller.instance, key),
                        value: value.clone(),
                    }
                }
                RecordMutation::Delete { kind, key } => {
                    let schema = schema_at(*kind, false)?;
                    Mutation::Delete {
                        schema: schema.as_str().to_string(),
                        key: record_key(&caller.instance, key),
                    }
                }
            });
        }
        let mut chains =
            zeroize::Zeroizing::new(Vec::<crate::host_chains::ConditionalChain>::new());
        let mut chain_scopes = std::collections::HashMap::new();
        for chain in &candidate.chains {
            use crate::host_chains::ConditionalChainAction;
            let (kind, scope, life) = match chain {
                ChainMutation::Append {
                    kind, scope, life, ..
                }
                | ChainMutation::Drop { kind, scope, life }
                | ChainMutation::Check { kind, scope, life } => (*kind, scope, life),
            };
            let schema = schema_at(kind, true)?;
            let scope =
                crate::host_chains::scope_of(scope).ok_or(crate::host_chains::CHAIN_SCOPE_UNFIT)?;
            let mut life = zeroize::Zeroizing::new(life.clone());
            let mut action = zeroize::Zeroizing::new(match chain {
                ChainMutation::Append { content, .. } => {
                    ConditionalChainAction::Append(vec![content.clone()])
                }
                ChainMutation::Drop { .. } => ConditionalChainAction::Drop,
                ChainMutation::Check { .. } => ConditionalChainAction::Check,
            });

            let address = (schema.as_str(), scope);
            if let Some(&index) = chain_scopes.get(&address) {
                let previous: &mut crate::host_chains::ConditionalChain = &mut chains[index];
                if previous.life != *life {
                    return Err("conflicting conditional chain observations");
                }
                match (&mut previous.action, &mut *action) {
                    (
                        ConditionalChainAction::Append(existing),
                        ConditionalChainAction::Append(additional),
                    ) => existing.append(additional),
                    _ => return Err("overlapping conditional chain operations"),
                }
                continue;
            }
            chain_scopes.insert(address, chains.len());
            let framing = chain_at(kind).ok_or(NOT_A_KIND)?;
            chains.reserve(1);
            chains.push(crate::host_chains::ConditionalChain {
                schema,
                scope: scope.to_string(),
                framing,
                life: std::mem::replace(
                    &mut *life,
                    busbar_contract::abi::sdk::store::conditional::Expected::Absent,
                ),
                action: std::mem::replace(&mut *action, ConditionalChainAction::Check),
            });
        }
        if chains.is_empty() {
            request
                .encode_held()
                .map_err(|_| "invalid record transaction")?;
        }
        let write = ConditionalWrite::new(
            Arc::clone(&caller.instance),
            request,
            chains,
            ConditionalOwed::new(candidate.correlation, acked),
            unit,
        );
        match self.batcher.push_conditional(write) {
            Some(true) => self.start_flush(records, pool),
            Some(false) => {}
            None => return Err(QUEUE_FULL),
        }
        Ok(())
    }

    fn chain_of(&self, caller: &Caller, kind: &str) -> Option<crate::host_chains::ChainFraming> {
        let facts = self.facts(caller)?;
        let index = facts.record_kinds.iter().position(|k| k.as_str() == kind)?;
        facts
            .record_chains
            .iter()
            .find(|c| c.kind as usize == index)
            .and_then(crate::host_chains::ChainFraming::of)
    }

    #[must_use]
    pub fn record_kind(&self, caller: &Caller, index: u32) -> Option<RecordSchemaId> {
        let facts = self.facts(caller)?;
        facts.record_kinds.get(index as usize).copied()
    }

    #[must_use]
    pub fn record_retention(&self, instance: &str, kind: &str) -> Retention {
        let Some(facts) = self.lock_instances().get(instance).cloned() else {
            return Retention::Age;
        };
        let Some(index) = facts.record_kinds.iter().position(|k| k.as_str() == kind) else {
            return Retention::Age;
        };
        facts
            .record_retentions
            .iter()
            .find(|r| r.kind as usize == index)
            .and_then(|r| Retention::from_code(r.rule))
            .unwrap_or_default()
    }

    pub fn purge_records_before(
        &self,
        store: &dyn RecordStore,
        instance: &str,
        kind: &str,
        before: u64,
    ) -> RecordStoreResult<u64> {
        if self.conditional_kind(instance, kind) {
            return Err(busbar_contract::records::RecordStoreError(
                "this record kind requires conditional retirement".into(),
            ));
        }
        store.purge_plane_records(kind, before, self.record_retention(instance, kind))
    }

    fn start_flush(&self, records: &Records, pool: &dyn Offload) {
        let unrun = Unrun(Some(Arc::clone(&self.batcher)));
        let pending = Arc::clone(&self.pending);
        let chains = Arc::clone(&self.chains);
        let rows = Arc::clone(&records.reads);
        pool.run(Box::new(move || {
            if let Some(batcher) = unrun.run() {
                batcher.flush(&pending, &*rows, &chains);
            }
        }));
    }

    pub fn flush_tick(&self) {
        if let (Some(records), Some(pool)) = (self.records.get(), self.pool()) {
            if self.batcher.start() {
                self.start_flush(records, pool);
            }
        }
    }

    /// Keep a live plane eligible for idle cancellation cleanup without retaining its instance.
    pub fn register_plane_cleanup(
        &self,
        driver: std::sync::Weak<crate::plane_driver::PlaneDriver>,
    ) {
        self.plane_cleanup
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(driver);
    }

    fn cleanup_planes(&self, cx: &mut std::task::Context<'_>) -> bool {
        let drivers = {
            let mut registered = self.plane_cleanup.lock().unwrap_or_else(|e| e.into_inner());
            registered.retain(|driver| driver.strong_count() != 0);
            registered
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .collect::<Vec<_>>()
        };
        let mut idle = true;
        for driver in drivers {
            idle &= driver.sweep_with_context(cx);
        }
        idle
    }

    /// Settle dropped callers before final billing flushes, retaining pending work on timeout.
    pub async fn drain_plane_cleanup(&self, deadline: std::time::Duration) -> bool {
        let until = tokio::time::Instant::now() + deadline;
        loop {
            if std::future::poll_fn(|cx| std::task::Poll::Ready(self.cleanup_planes(cx))).await {
                return true;
            }
            if tokio::time::Instant::now() >= until {
                return false;
            }
            tokio::time::sleep_until(std::cmp::min(
                until,
                tokio::time::Instant::now() + std::time::Duration::from_millis(2),
            ))
            .await;
        }
    }

    pub async fn flushes(&self) {
        use futures::StreamExt as _;
        let every = crate::host_records::FLUSH_INTERVAL;
        let mut at = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        at.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut jobs = futures::stream::FuturesUnordered::new();
        loop {
            tokio::select! {
                _ = at.tick() => {
                    std::future::poll_fn(|cx| std::task::Poll::Ready(self.cleanup_planes(cx))).await;
                    self.flush_tick();
                    self.verify_tick();
                    self.trust_resync_tick();
                    let wall = std::time::UNIX_EPOCH
                        + std::time::Duration::from_millis((self.wall_ms)());
                    jobs.extend(crate::tick::beat(wall));
                }
                Some(()) = jobs.next(), if !jobs.is_empty() => {}
            }
        }
    }

    pub fn trust_resync_tick(&self) {
        use std::sync::atomic::Ordering;
        let (Some(d), Some(pool)) = (self.demotions.get(), self.pool()) else {
            return;
        };
        let now = (self.wall_ms)() / 1000;
        let (last, running) = &*self.trust_resync;
        if now.saturating_sub(last.load(Ordering::Relaxed))
            < crate::governance::REVOCATION_SYNC_TTL_SECS
            || running.swap(true, Ordering::Acquire)
        {
            return;
        }
        let resync = TrustResync(Arc::clone(&self.trust_resync));
        last.store(now, Ordering::Relaxed);
        let (record, trust) = (Arc::clone(&d.record), Arc::clone(&self.trust));
        pool.run(Box::new(move || {
            let _resync = resync;
            let snapshot = trust.decision_snapshot();
            match record.decisions() {
                Ok(rows) => trust.resync_decided(&snapshot, &rows),
                Err(why) => crate::diagnostics::diag_warn!(
                    crate::diagnostics::REVOCATION_RESYNC_FAILED,
                    error = %why,
                    "the operator's trust decisions could not be re-read; keeping the decisions \
                     already applied (one made through another node may not be in force here \
                     until the next successful re-read)"
                ),
            }
        }));
    }

    pub fn verify_tick(&self) {
        self.verify.expire((self.wall_ms)());
    }

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
    fn owner_of_unit(&self, unit: Option<u64>) -> Option<Owner> {
        let record = self.units.get(unit?)?;
        Some(owner_of(record.principal.as_deref().map(|k| k.id.as_str())))
    }

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

fn work_found(handle: u64, w: &Work) -> Stored {
    let mut s = spans_of(vec![(vec![w.state()], w.record.clone())]);
    s.value = handle;
    s
}

pub const NOT_ADMITTED: &str = "the instance is not admitted";

pub const NOT_A_KIND: &str = "not a record kind the instance declared";

pub const NO_STORE: &str = "no store is bound";

pub const NO_TTL: &str = "a claim states its time to live";

pub const EXPIRY_OVERFLOW: &str = "the claim's expiry overflows";

pub const NO_DOMAIN: &str = "the instance declares no signing domain";

pub const NO_KEY: &str = "no signing key is configured";

pub const NOT_A_COUNTERPARTY: &str = "not a counterparty the instance declares";

pub const NO_ROOT_KEY: &str = "the counterparty declares no root key";

pub const SIGNATURES_NOT_JSON: &str = "the signatures are not one JSON document";

pub const NO_POOL: &str = "no pool is bound";

pub const POOL_REFUSED: &str = "the pool refused the store call";

pub const STORE_FAILED: &str = "the store did not answer";

pub const DECISION_UNKEPT: &str = "the trust decision could not be kept";

pub const NO_CREDENTIAL_SOURCE: &str = "no credential source";

pub const NOT_READABLE: &str = "the credential read is not installed yet";

pub const FILL_OUT_OF_RANGE: &str = "a fill asks for 1 to MAX_RANDOM_FILL bytes";

pub const NO_RANDOMNESS: &str = "the OS randomness source failed";

fn failed(why: &'static str) -> Stored {
    Stored {
        outcome: Outcome::Failed,
        bytes: Vec::new(),
        spans: Vec::new(),
        ..Stored::refused(why)
    }
}

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
    /// The fingerprint the caller approves is not the key's current sighting, or another local
    /// mutation currently owns its durable decision key.
    Stale,
    /// The key's current sighting failed its verification
    /// ([`crate::trust::book::UNVERIFIED_SIGHTING`]): nothing verified to approve.
    Unverified,
    /// The decision could not be kept; the store's words, for the node's log.
    Store(String),
}

pub const DEMOTION_SEP: char = '\u{1f}';

#[must_use]
pub fn demotion_key(instance: &str, counterparty: &str) -> String {
    format!("{instance}{DEMOTION_SEP}{counterparty}")
}

#[must_use]
pub fn claim_token(instance: &str, kind: &str, key: &[u8]) -> String {
    let digest = busbar_contract::abi::sdk::digest::sha256(
        &[instance.as_bytes(), &[0], kind.as_bytes(), &[0], key].concat(),
    );
    let minted = IdempotencyKey::mint(&crate::seal::acquire(), digest);
    hex::encode(minted.bytes())
}

impl HostServices for KernelServices {
    fn observe_chain_life(
        &self,
        caller: &Caller,
        kind: u32,
        scope: &[u8],
        done: crate::host_records::ChainLifeAcked,
    ) -> Result<(), &'static str> {
        KernelServices::observe_chain_life(self, caller, kind, scope, done)
    }

    fn supports_record_transactions(&self) -> bool {
        KernelServices::supports_record_transactions(self)
    }

    fn conditional_record_transaction(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        candidate: crate::host_records::ConditionalCandidate,
        acked: crate::host_records::ConditionalAcked,
    ) -> Result<(), &'static str> {
        self.record_transaction(caller, unit, candidate, acked)
    }

    fn inspect(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        query: &busbar_contract::abi::mechanism::inspection::InspectionQuery,
    ) -> busbar_contract::abi::mechanism::inspection::InspectionResult {
        use busbar_contract::abi::mechanism::inspection::{
            InspectionError, InspectionObservation, InspectionQuery, SessionObservation,
            WorkObservation,
        };
        if self.facts(caller).is_none() {
            return Err(InspectionError::Refused);
        }
        match query {
            InspectionQuery::Work { reference } => {
                let owner = self.owner_of_unit(unit).ok_or(InspectionError::Refused)?;
                let reference = parse_reference(reference).ok_or(InspectionError::NotFound)?;
                let (_, work) = self
                    .work
                    .by_reference(&caller.instance, &reference)
                    .filter(|(_, work)| work.owner == owner)
                    .ok_or(InspectionError::NotFound)?;
                let retain_ms = self.work_bounds_of(&caller.instance).retain_ms;
                let observed_ms = (self.wall_ms)();
                if !work.live && work.settled_ms.saturating_add(retain_ms) <= observed_ms {
                    return Err(InspectionError::NotFound);
                }
                Ok(InspectionObservation::Work(WorkObservation {
                    observed_ms,
                    opened_ms: work.opened_ms,
                    retain_ms,
                    settled_ms: (!work.live).then_some(work.settled_ms),
                }))
            }
            InspectionQuery::CarrierSessions { sessions } => {
                let open = self
                    .sessions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let observations = sessions
                    .iter()
                    .map(|session| SessionObservation {
                        session: *session,
                        live: open
                            .get(session)
                            .is_some_and(|held| held.instance == caller.instance),
                    })
                    .collect();
                Ok(InspectionObservation::CarrierSessions(observations))
            }
        }
    }

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
        if self.chain_of(caller, kind).is_some() {
            return Ran::Now(Stored::refused(crate::host_chains::CHAIN_READ_WHOLE));
        }
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
        let chain = self.chain_of(caller, &list.kind);

        let queued = match chain {
            Some(_) => Vec::new(),
            None => self
                .pending
                .under(&caller.instance, &list.kind, &list.prefix),
        };
        let reads = Arc::clone(&records.reads);
        let instance = Arc::clone(&caller.instance);
        let scope = record_key(&caller.instance, &[]).len();
        let prefix = record_key(&caller.instance, &list.prefix);

        submit(pool, later, move || {
            match reads.record_scan(schema, &prefix, u32::MAX) {
                Ok(rows) => {
                    let rows: Vec<(Vec<u8>, Vec<u8>)> = rows
                        .into_iter()
                        .filter_map(|(k, v)| {
                            Some((k.get(scope..)?.to_vec(), v.as_slice().to_vec()))
                        })
                        .collect();
                    let rows = match chain {
                        Some(f) => crate::host_chains::verified(&instance, schema, rows, f),
                        None => rows,
                    };
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

        let now = now_ms / 1000;
        let expires_at = expires_ms.div_ceil(1000);
        let token = claim_token(&caller.instance, kind, key);
        let rows = Arc::clone(&records.reads);
        let kind = kind.to_string();
        submit(pool, later, move || {
            match rows.claim(&kind, &token, expires_at, now) {
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
        let durable = match (self.demotions.get(), self.pool()) {
            (Some(_), None) => return Ran::Now(Stored::refused(NO_POOL)),
            (Some(d), Some(pool)) => Some((d, pool)),
            (None, _) => None,
        };

        let permit = match self
            .trust
            .begin_sighting(&caller.instance, counterparty, None)
        {
            Ok(permit) => permit,
            Err(Undecided::NoSuchKey) => {
                return Ran::Now(Stored::refused(if self.facts(caller).is_some() {
                    NOT_A_COUNTERPARTY
                } else {
                    NOT_ADMITTED
                }));
            }
            Err(_) => return Ran::Now(Stored::refused(DECISION_UNKEPT)),
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
        let answer = Stored::ready(sight_code(sight));
        let Some((d, pool)) = durable.filter(|_| effect != Effect::None) else {
            return Ran::Now(answer);
        };

        let record = Arc::clone(&d.record);
        let key = demotion_key(&caller.instance, counterparty);

        let unprefixed = (caller.instance == d.default_instance).then(|| counterparty.to_string());
        let owed = TrustSightOwed {
            permit: Some(permit),
            later: Some(later),
        };
        pool.run(Box::new(move || {
            let settle = |server: &str, state| {
                crate::trust::demotion::settle(&record, server, state);
            };
            if effect == Effect::Demote {
                settle(&key, crate::trust::TrustState::Quarantined);
            } else {
                settle(&key, crate::trust::TrustState::Approved);
                if let Some(cp) = unprefixed {
                    settle(&cp, crate::trust::TrustState::Approved);
                }
            }
            owed.answer(answer);
        }));
        Ran::Later
    }

    fn entitlement_check(&self, caller: &Caller, unit: Option<u64>, target: &str) -> Stored {
        Stored::ready(if self.entitled(caller, unit, target) {
            svc::ENTITLED
        } else {
            svc::NOT_ENTITLED
        })
    }

    fn records_secret(&self, kind: &str, id: &str, _later: Later) -> Ran {
        let Some(credentials) = self.credentials.as_ref() else {
            return Ran::Now(Stored::refused(NO_CREDENTIAL_SOURCE));
        };
        if !credentials.installed() {
            return Ran::Now(Stored::refused(NOT_READABLE));
        }
        let (secret, live) = credentials.read(kind, id);
        let bytes = secret.expose(&crate::seal::lend()).as_bytes().to_vec();
        let span = ItemSpan {
            key: absent_span(),
            value: Span {
                offset: 0,
                len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            },
        };
        Ran::Now(Stored {
            bytes,
            spans: vec![span],
            ..Stored::ready(if live {
                svc::SECRET_LIVE
            } else {
                svc::SECRET_NOT_LIVE
            })
        })
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

        crate::audit::auditlog::emit_admin_hostless_now(
            SESSION_EMIT_ACTION,
            &format!("session:{session}"),
            busbar_contract::vocab::OUTCOME_APPLIED,
            &principal,
        );
        Stored::ready(0)
    }

    fn ticket_mint(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        ttl_secs: u64,
        record: &[u8],
    ) -> Stored {
        let Some(key) = unit
            .and_then(|u| self.units.get(u))
            .and_then(|r| r.principal.clone())
        else {
            return Stored::refused(TICKET_NO_PRINCIPAL);
        };
        let Some(prefix) = self.facts(caller).and_then(|f| f.ticket_prefix.clone()) else {
            return Stored::refused(TICKET_NO_PREFIX);
        };
        let Some(press) = self.tickets.get() else {
            return Stored::refused(TICKET_NO_PRESS);
        };
        let now = (self.wall_ms)() / 1000;
        match press.mint(&key.id, &prefix, ttl_secs, record, now) {
            Ok((ticket, expires_at)) => Stored {
                bytes: ticket.into_bytes(),
                spans: Vec::new(),
                ..Stored::ready(expires_at)
            },
            Err(why) => Stored::refused(why),
        }
    }

    fn ticket_take(&self, _caller: &Caller, unit: Option<u64>) -> Stored {
        match unit.and_then(|u| self.units.take_ticket(u)) {
            Some(Some(record)) => Stored {
                bytes: record,
                spans: Vec::new(),
                ..Stored::ready(svc::TICKET_TAKEN)
            },
            Some(None) => Stored::ready(svc::TICKET_NONE),
            None => Stored::refused(TICKET_NOT_HELD),
        }
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
            spans: Vec::new(),
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

                Err(TrustRefused::Unverified) => svc::UNDECIDED_UNPINNED,
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
        let mut permit = match self
            .trust
            .begin_sighting(&caller.instance, counterparty, Some(item))
        {
            Ok(permit) => permit,
            Err(Undecided::NoSuchKey) => {
                return Stored::refused(if self.facts(caller).is_some() {
                    NOT_A_COUNTERPARTY
                } else {
                    NOT_ADMITTED
                });
            }
            Err(_) => return Stored::refused(DECISION_UNKEPT),
        };
        match self
            .trust
            .sight_item_kept(&caller.instance, counterparty, item, digest)
        {
            Ok((sight, demotion)) => {
                if demotion.is_some() {
                    permit.demoted();
                }

                if let (Some(fact), Some(d)) = (demotion, self.demotions.get()) {
                    if let Err(why) = d.record.keep_decision(&fact, (self.wall_ms)() / 1000) {
                        tracing::error!(
                            counterparty,
                            item,
                            error = %why,
                            "an item's drift demotion could not be kept; it holds in this process"
                        );
                    }
                }
                Stored::ready(sight_code(sight))
            }
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
            spans: Vec::new(),
            ..Stored::ready(value)
        }
    }

    fn unit_nest(&self, caller: &Caller, unit: Option<u64>, ask: NestAsk, later: Later) -> Ran {
        if self.facts(caller).is_none() {
            return Ran::Now(Stored::refused(NOT_ADMITTED));
        }

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
                opened_by: unit,
            };
            let Some(row) = work.row() else {
                return Stored::refused(work_refusal::TOO_LONG);
            };

            let Some(handle) = book.reserve(work, bounds.max_live) else {
                return Stored::refused(work_refusal::AT_BOUND);
            };

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
        let (Some(unit), Some(owner)) = (unit, self.owner_of_unit(unit)) else {
            return Ran::Now(Stored::refused(work_refusal::NO_UNIT));
        };
        let units = Arc::clone(&self.units);

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
                    book.found(handle, unit, &|u| units.get(u).is_some());
                    work_found(handle, &w)
                }
                _ => absent(),
            }
        })
    }

    fn work_settle(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        handle: u64,
        record: &[u8],
        later: Later,
    ) -> Ran {
        let (_, records, pool) = match self.work_scope(caller) {
            Ok(s) => s,
            Err(refused) => return Ran::Now(refused),
        };
        if record.len() > svc::MAX_WORK_RECORD {
            return Ran::Now(Stored::refused(work_refusal::TOO_LONG));
        }
        let now_ms = (self.wall_ms)();

        let owner = self.owner_of_unit(unit);
        let in_flight = |u: u64| self.units.get(u).is_some();
        let settled = match self.work.settle(
            &caller.instance,
            handle,
            owner.as_ref(),
            &in_flight,
            record.to_vec(),
            now_ms,
        ) {
            Ok(v) => v,
            Err(why) => return Ran::Now(Stored::refused(why)),
        };
        let Some(row) = settled.row() else {
            self.work.cancel_settle(handle);
            return Ran::Now(Stored::refused(work_refusal::TOO_LONG));
        };

        let unwritten = Unwritten {
            book: Arc::clone(&self.work),
            handle,
            settled: Some(settled.clone()),
            later: Some(later),
        };
        let rows = Arc::clone(&records.reads);
        let key = work_key(&caller.instance, &settled.reference);
        pool.run(Box::new(move || {
            let confirmed = rows.record_put(WORK_SCHEMA, &key, &row).is_ok();
            unwritten.answer(confirmed);
        }));
        Ran::Later
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
                Ok(w) => {
                    let mut stored = work_found(handle, &w);
                    stored.value = 0;
                    stored
                }
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
                        spans: Vec::new(),
                        ..Stored::ready(1 + u64::from(index))
                    },
                    StageAnswer::Stop { status, words } => Stored {
                        bytes: words.into_bytes(),
                        spans: Vec::new(),
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

pub const STAGE_NO_UNIT: &str = "the crossing serves no unit in flight";

pub const STAGE_NOT_BOUND: &str = "the unit's hook stage is not bound yet";

pub const STAGE_NOT_YOURS: &str = "the unit runs on another instance";

pub const STAGE_ANSWERED_AMISS: &str = "the hook stage answered outside the service's shape";

impl KernelServices {
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

pub type Judged = Box<dyn FnOnce(Result<SocketAddr, u64>) + Send>;

pub type Admitted = Result<(SocketAddr, Vec<IpAddr>), Refused>;

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

const fn absent_span() -> Span {
    Span {
        offset: busbar_contract::abi::mechanism::check::SPAN_ABSENT,
        len: 0,
    }
}

#[cfg(test)]
#[path = "tests/host_services_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "tests/trust_verify_tests.rs"]
mod trust_verify_tests;

#[cfg(test)]
#[path = "tests/trust_rule_tests.rs"]
mod trust_rule_tests;

#[cfg(test)]
#[path = "tests/host_nest_tests.rs"]
mod host_nest_tests;

#[must_use]
pub fn decided_code(state: KeyState) -> u64 {
    match state {
        KeyState::Same | KeyState::Approved => svc::TRUST_DECIDED_SERVING,
        KeyState::New => svc::TRUST_DECIDED_PENDING,
        KeyState::Drifted | KeyState::Quarantined => svc::TRUST_DECIDED_QUARANTINED,
    }
}

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

#[must_use]
pub fn sight_code(sight: Sight) -> u64 {
    match sight {
        Sight::New => svc::TRUST_NEW,
        Sight::Same => svc::TRUST_SAME,
        Sight::Drifted => svc::TRUST_DRIFTED,
        Sight::Quarantined => svc::TRUST_QUARANTINED,
    }
}

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

#[cfg(test)]
#[path = "tests/host_chains_tests.rs"]
mod chain_tests;
