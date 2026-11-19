// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use foldhash::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use busbar_contract::abi::host::service::{self as svc, ItemSpan, MAX_SPANS};
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::caps::IdempotencyKey;
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::Retention;
use busbar_contract::services::{
    merge_list, Caller, CredentialRead, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran,
    Reading, RecordsList, Stored,
};

#[path = "host_observations.rs"]
mod observations_runtime;

#[path = "host_recovery.rs"]
mod recovery_runtime;
pub(crate) use recovery_runtime::recovery_binding_of;
pub(crate) use recovery_runtime::ActiveSet;
pub use recovery_runtime::RecoveryWork;

pub const QUEUE_FULL: &str = "the record write queue is full";

#[path = "invocation.rs"]
mod invocation;
pub use invocation::{InvocationContext, NativeInvocationAdmission, ServingGeneration};

#[cfg(test)]
#[path = "tests/invocation_context_tests.rs"]
mod invocation_context_tests;

use crate::host_records::{
    record_key, Acked, Owed as WriteOwed, PendingRecords, RecordRows, Write, WriteBehind,
};
use crate::host_units::StageAnswer;
use crate::host_work::{
    owner_of, parse_reference, reference_text, refusal as work_refusal, Owner, Work, WorkBook,
    WorkBounds, WORK_SCHEMA,
};
use crate::trust::book::{
    DecidedBy, Distrust, Effect, KeyRow, KeyState, Reviewed, Ruling, Sight, TrustBook, TrustFacts,
    Undecided, Unjudged,
};
use crate::trust::demotion::{DemotionRecord, Verdict, WriteFailure};
use crate::trust::section::TrustEntry;
use crate::trust::signed;

/// A destination whose transport already supplied authority and security intent. The intent is
/// independent of its spelling and is not evidence that connection security has completed.
#[derive(Debug, Clone, Copy)]
pub struct Destination<'a> {
    pub authority: &'a str,
    pub secure: bool,
    pub egress_class: u32,
}

pub trait DestJudge: Send + Sync {
    /// Judge a transport-located target without interpreting a URL scheme.
    fn judge_target_name(&self, target: Destination<'_>, refuse_private: bool) -> Result<(), u64> {
        let _ = (target, refuse_private);
        Err(svc::DEST_SCHEME)
    }

    /// Resolve and pin the located target; a missing implementation fails closed.
    fn judge_target(
        &self,
        target: Destination<'_>,
        refuse_private: bool,
        reach: bool,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        let _ = (target, refuse_private, reach, done);
        Some(Err(svc::DEST_SCHEME.into()))
    }

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

    /// THE PLAINTEXT RULE for `dest` (a URL or `host[:port]`), as a judge alone knows it: admitted
    /// only to a host an exact `advanced.tls.destinations` entry admits plaintext to. SEC-2 (#297
    /// model A): no loopback address or name is exempt; an instance's own plaintext acceptance is
    /// its core-held `insecure_transport.accept`, applied where its dial is opened. The default
    /// knows no entries: nothing.
    fn plaintext_admitted(&self, dest: &str) -> bool {
        let _ = dest;
        false
    }

    fn judge_host(&self, host: &str, class: u32) -> Result<(), DestRefusal> {
        self.judge_name(host, class, false)
            .map_err(|verdict| DestRefusal {
                verdict,
                reason: crate::cold::host::services_host_refused(host),
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
    fn nest(&self, context: InvocationContext, nest: Nest, done: NestDone);
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
    /// Initiating hooks, inherited through ordinary nesting as well.
    pub ancestry: Vec<Arc<str>>,
    /// Configured hook authority, absent for ordinary plane nesting.
    pub constraints: Option<crate::hook_child::Constraints>,
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

pub(crate) const NEST_FULL: &str = "the node runs as many nested units as it holds";

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

pub(crate) const NO_DEST_JUDGE: &str = "no destination judge is installed";

/// BUSBAR-6014: `dest.judge` refuses the operator-infrastructure egress class from a plugin. That
/// class is a property of a config-declared target, never a plugin's choice; a host named inside
/// content is judged in the default or open-web class.
const DEST_JUDGE_OPERATOR_INFRASTRUCTURE: &str = "BUSBAR-6014: dest.judge refuses the \
     operator-infrastructure egress class: that class belongs to a target the operator configured, \
     never to a host a plugin names; judge it in the default or open-web class";

/// Whether the refusal of a plugin's operator-infrastructure `dest.judge` was already logged and
/// audited (once per process: the service carries no caller).
static DEST_JUDGE_CLASS_FLAGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub type AsyncJob = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;

pub trait Offload: Send + Sync {
    fn run(&self, job: Box<dyn FnOnce() + Send>);
    /// Existing executors opt into asynchronous host jobs. Dropping an unrun job
    /// preserves the same callback refusal behavior as the blocking lane.
    fn run_async(&self, job: AsyncJob) {
        drop(job);
    }
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
    fn run_async(&self, job: AsyncJob) {
        use std::sync::atomic::Ordering;
        if self.held.fetch_add(1, Ordering::AcqRel) >= self.bound {
            self.held.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        let place = Place(Arc::clone(&self.held));
        drop(self.handle.spawn(async move {
            let _place = place;
            job.await;
        }));
    }

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

#[cfg(test)]
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
        result: Result<busbar_contract::host_records::conditional::Expected, &'static str>,
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

fn native_record_found(value: Vec<u8>) -> Stored {
    if value.is_empty() {
        return Stored::ready(svc::ABSENT);
    };
    let mut stored = Stored::ready(svc::FOUND);
    let length = value.len();
    stored.bytes = value;
    stored.spans.push(ItemSpan {
        key: absent_span(),
        ..span(0, 0, 0, length)
    });
    stored
}

fn submit_async(
    pool: &dyn Offload,
    later: Later,
    job: impl std::future::Future<Output = Stored> + Send + 'static,
) -> Ran {
    let owed = Owed(Some(later));
    pool.run_async(Box::pin(async move {
        owed.answer(job.await);
    }));
    Ran::Later
}

pub trait SignKey: Send + Sync {
    /// Signs `data` in `domain`: appends the signature, then the signing key's id, to `out` (the
    /// answer's own buffer) and answers the signature's length. `None` = no key, and `out` is
    /// left as it was.
    fn sign(&self, domain: &str, data: &[u8], out: &mut Vec<u8>) -> Option<usize>;
}

impl SignKey for crate::governance::GovState {
    fn sign(&self, domain: &str, data: &[u8], out: &mut Vec<u8>) -> Option<usize> {
        self.sign_in_domain(domain, data, out)
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
    /// Validated collection declarations; kind and parent indices are instance-local.
    pub record_collections: Vec<busbar_contract::abi::plane::RecordCollection>,
    /// Declared kind indices requiring conditional publication, established before admission.
    /// Ordinary record writes must never share these namespaces with conditional candidates.
    pub conditional_record_kinds: Vec<u32>,
    /// Its signing declaration; `None` = `sign` is refused.
    pub signing: Option<Signing>,
    /// Its trust entries, one per counterparty, as `trust::section` parsed them.
    pub trust: Vec<(String, TrustEntry)>,
    /// The scope kinds its tail declares: a scope check answers only for these.
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

/// Verified, in-process ticket identity. Its credential remains host-private and zeroised.
pub struct VerifiedTicketIdentity {
    pub(crate) id: String,
    pub(crate) principal: Arc<busbar_contract::records::VirtualKey>,
    pub(crate) expires_at: u64,
    pub(crate) store: Arc<crate::persistence::facade::CoreStore>,
    pub(crate) prefix: String,
    pub(crate) credential: busbar_contract::secure::SecureString,
}

impl VerifiedTicketIdentity {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn principal(&self) -> &Arc<busbar_contract::records::VirtualKey> {
        &self.principal
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn store(&self) -> &Arc<crate::persistence::facade::CoreStore> {
        &self.store
    }
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}

impl std::fmt::Debug for VerifiedTicketIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedTicketIdentity")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Host policy classifies an authenticated ticket before its durable single-use spend.
pub enum TicketClaimDisposition {
    Ordinary,
    Reserved(crate::plane_driver::TicketReservation),
    Refused,
}

/// Shared request contexts carry one removable, durably spent reservation.
/// Cloning this holder shares custody; it never clones the reservation itself.
#[derive(Clone)]
pub struct HostTicketAdmission(Arc<Mutex<Option<crate::plane_driver::SpentTicketReservation>>>);

impl HostTicketAdmission {
    pub(crate) fn new(spent: crate::plane_driver::SpentTicketReservation) -> Self {
        Self(Arc::new(Mutex::new(Some(spent))))
    }

    pub fn take(&self) -> Option<crate::plane_driver::SpentTicketReservation> {
        let mut held = self.0.lock().ok()?;
        held.take()
    }
}

impl std::fmt::Debug for HostTicketAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostTicketAdmission")
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
pub trait TicketPress: Send + Sync {
    /// Mint with the host's exact admitted unit and caller identity. Reservation-aware presses
    async fn mint_for_unit(
        &self,
        unit: u64,
        caller: &Caller,
        principal: &Arc<busbar_contract::records::VirtualKey>,
        prefix: &str,
        ttl_secs: u64,
        record: &[u8],
        now: u64,
    ) -> Result<(String, u64), crate::governance::TicketRefusal> {
        let _ = (unit, caller);
        self.mint(&principal.id, prefix, ttl_secs, record, now)
            .await
    }

    async fn mint(
        &self,
        key_id: &str,
        prefix: &str,
        ttl_secs: u64,
        record: &[u8],
        now: u64,
    ) -> Result<(String, u64), crate::governance::TicketRefusal>;
}

pub const TICKET_NO_PRINCIPAL: &str = "no ticket is minted outside a unit with a principal";

pub const TICKET_NO_PREFIX: &str = "no ticket is minted for an instance that declares no prefix";

pub const TICKET_NO_PRESS: &str = "this host mints no tickets";

pub const TICKET_NOT_HELD: &str = "no ticket record is held for this unit";

pub(crate) const RESERVED_RECORD_KINDS: &[&str] = &[
    recovery_runtime::CALLERS,
    crate::governance::TICKET_RECORD_KIND,
    crate::host_work::WORK_SCHEMA.as_str(),
    crate::host_record_bootstrap::RECEIPT_SCHEMA.as_str(),
    crate::governance::principal_transition::SCHEMA.as_str(),
    crate::host_chains::CHAIN_LIFE_SCHEMA.as_str(),
];

/// Why an instance was not admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitRefused {
    /// A cold bootstrap namespace cannot admit another generation in this process.
    ///
    /// Every instance label a refusal names is the shared label its holder already has (the
    /// label admission was called with, or the admitted instance's key): a refusal copies none.
    BootstrapHeld { instance: Arc<str> },
    /// The label is longer than 65535 bytes or holds a control character: every per-instance key
    /// is built from it, and only a label without them keeps those keys apart.
    LabelUnfit {
        /// The label's length in bytes.
        len: usize,
    },
    /// Another instance holds the signing domain the instance declares.
    DomainHeld {
        /// The domain: the refused declaration's own, moved out of it.
        domain: String,
        /// The instance holding it.
        held_by: Arc<str>,
        /// The instance refused.
        asked_by: Arc<str>,
    },
    /// Another instance owns this delegated-credential consumer namespace.
    TicketPrefixHeld {
        /// The declared namespace: the refused declaration's own, moved out of it.
        prefix: String,
        /// The instance holding it.
        held_by: Arc<str>,
        /// The instance refused.
        asked_by: Arc<str>,
    },
    /// An admitted instance tried to release a namespace whose credentials may remain live.
    TicketPrefixChanged {
        /// The admitted instance.
        instance: Arc<str>,
        /// Its original namespace.
        prefix: String,
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
    /// Native claim retention could not bind an admitted record scope.
    ClaimMaintenance {
        /// The declared record kind: its schema's own name.
        kind: &'static str,
    },
    /// The store could not be read for the demotions and the operator's trust decisions this
    /// instance's trust stands on.
    TrustUnread(String),
    /// The instance declares a record kind the kernel keeps its own records under
    /// ([`RESERVED_RECORD_KINDS`]): its retention rule would govern the kernel's own rows.
    KindReserved {
        /// The instance refused.
        instance: Arc<str>,
        /// The reserved kind it declares: its schema's own name.
        kind: &'static str,
    },
}

impl std::fmt::Display for AdmitRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BootstrapHeld { instance } => write!(f, "instance `{instance}` holds a cold record bootstrap grant; another generation requires a cold restart"),
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
            Self::TicketPrefixHeld {
                prefix,
                held_by,
                asked_by,
            } => write!(
                f,
                "instance `{asked_by}` declares credential consumer prefix `{prefix}`, which \
                 instance `{held_by}` holds: no instance redeems another's credentials"
            ),
            Self::TicketPrefixChanged { instance, prefix } => write!(
                f,
                "instance `{instance}` cannot change credential consumer prefix `{prefix}` \
                 while credentials issued under it may remain live"
            ),
            Self::ChainUnknown { kind, framing } => write!(
                f,
                "the instance declares chained record kind {kind} with framing {framing}, which \
                 this host cannot chain: a declared chain is kept, never dropped to plain records"
            ),
            Self::ConditionalKind { kind } => write!(f, "invalid conditional record kind {kind}"),
            Self::ClaimMaintenance {kind}=>write!(f,"native claim retention could not be registered for record kind `{kind}`"),
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

struct NativeRecordScope {
    rows: crate::host_records_async::AsyncRecords,
    facts: Arc<InstanceFacts>,
    /// The declared kind the op names.
    schema: RecordSchemaId,
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

/// Nanoseconds since `origin` on the node's monotonic clock (one reading), saturating.
fn since_origin_ns(origin: Instant) -> u64 {
    u64::try_from(crate::store::elapsed(origin).as_nanos()).unwrap_or(u64::MAX)
}

struct NativeWorkWriter {
    instance: Arc<str>,
    store: Arc<crate::persistence::facade::CoreStore>,
    batcher: Arc<WriteBehind>,
    pending: Arc<PendingRecords>,
    chains: Arc<crate::host_chains::ChainBook>,
    pool: Arc<dyn Offload>,
}
impl NativeWorkWriter {
    fn rows(
        &self,
    ) -> Result<crate::persistence::scoped::ScopedStore, crate::persistence::scoped::Error> {
        crate::persistence::scoped::ScopedStore::host_private(
            Arc::clone(&self.store),
            &self.instance,
            [WORK_SCHEMA.as_str()],
        )
    }
    fn put(&self, key: Vec<u8>, value: RecordBytes, acked: Acked) {
        let instance = Arc::clone(&self.instance);
        let owed = WriteOwed::new(acked);
        let batcher = Arc::clone(&self.batcher);
        let pending = Arc::clone(&self.pending);
        let store = Arc::clone(&self.store);
        let chains = Arc::clone(&self.chains);
        // Before its first poll the scheduled job owns the unsent write. A pool
        // refusal drops that owner and answers its caller without queuing a write.
        self.pool.run_async(Box::pin(async move {
            if batcher.push_native_private_with(move || Write {
                instance,
                schema: WORK_SCHEMA,
                key,
                value: crate::host_records::WriteBytes::Own(value),
                seq: 0,
                owed,
                chain: None,
            }) == Some(true)
            {
                // A false result leaves this write with the existing driver.
                // Once admitted, flush_native retains exact uncertain custody.
                batcher.flush_native(&pending, &store, &chains).await;
            }
        }));
    }
}

struct WorkOpening {
    book: Arc<WorkBook>,
    handle: u64,
    reference: crate::host_work::Reference,
    owed: Option<Owed>,
}
impl WorkOpening {
    fn answer(mut self, result: Result<(), &'static str>) {
        let stored = if result.is_ok() {
            let text = reference_text(&self.reference).into_bytes();
            let len = text.len();
            let mut stored = Stored::ready(self.handle);
            stored.bytes = text;
            stored.spans.push(ItemSpan {
                value: absent_span(),
                ..span(0, len, 0, 0)
            });
            stored
        } else {
            self.book.unreserve(self.handle);
            failed(STORE_FAILED)
        };
        if let Some(owed) = self.owed.take() {
            owed.answer(stored);
        }
    }
}
impl Drop for WorkOpening {
    fn drop(&mut self) {
        if self.owed.is_some() {
            self.book.unreserve(self.handle);
        }
    }
}

type NativeClaimKey = (Arc<str>, RecordSchemaId, String);
#[derive(Clone, Copy)]
struct NativeClaimAttempt {
    expires_at: u64,
    pending: Option<crate::persistence::scoped::PendingClaim>,
    driving: bool,
}
type NativeClaims = Arc<Mutex<HashMap<NativeClaimKey, NativeClaimAttempt>>>;
struct NativeClaimGuard {
    claims: NativeClaims,
    key: NativeClaimKey,
}
impl Drop for NativeClaimGuard {
    fn drop(&mut self) {
        if let Some(attempt) = self
            .claims
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(&self.key)
        {
            attempt.driving = false;
        }
    }
}

type TrustDecisionKey = (
    busbar_contract::services::Incarnation,
    busbar_contract::abi::mechanism::ticket::Ticket,
);
const NO_TRUST_DECISION_GRANT: &str = "this call has no core-issued trust decision grant";

/// The counterparty a trust decision grant is bound to: an entry of the granted instance's own
/// trust facts, shared rather than copied.
struct GrantedCounterparty {
    facts: Arc<InstanceFacts>,
    index: usize,
    authority: TrustDecisionAuthority,
    request_id: Option<String>,
}

/// THE ADMIN AUTHORITY a plane-relayed trust decision runs under (r3 §4.2a, condition B-C1).
/// Built only by the admin gate from its own admission verdict and the caller's verb grant, never
/// from request headers or from a principal alone. Absent: the plane may not decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDecisionAuthority {
    /// The resolved principal.
    pub principal: String,
    /// The grant admits `trust_approve`.
    pub approve: bool,
    /// The grant admits `trust_revoke`.
    pub revoke: bool,
}

impl TrustDecisionAuthority {
    fn admits(&self, ruling: Ruling) -> bool {
        match ruling {
            Ruling::Approve => self.approve,
            Ruling::Revoke => self.revoke,
        }
    }
}
impl GrantedCounterparty {
    fn name(&self) -> &str {
        self.facts
            .trust
            .get(self.index)
            .map_or("", |(name, _)| name.as_str())
    }
}

/// Held only while core serves an authorized private administrative write. Neither
/// a plugin's kind nor its request bytes can create this authority.
pub(crate) struct TrustDecisionGrant<'a> {
    services: &'a KernelServices,
    key: TrustDecisionKey,
}
impl Drop for TrustDecisionGrant<'_> {
    fn drop(&mut self) {
        self.services
            .trust_decisions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key);
    }
}

pub struct KernelServices {
    observations: observations_runtime::ObservationRuntime,
    outbound: crate::host_outbound::Custody,
    origin: Instant,
    wall_ms: WallMs,

    mono_ns: Option<MonoNs>,
    instances: Mutex<HashMap<Arc<str>, Arc<InstanceFacts>>>,
    native_invocations: Mutex<std::collections::HashSet<busbar_contract::services::Incarnation>>,
    trust_decisions: Mutex<HashMap<TrustDecisionKey, GrantedCounterparty>>,
    record_bootstrap: Mutex<Option<crate::host_record_bootstrap::Bootstrap>>,
    native_record_bootstrap: Mutex<HashMap<Arc<str>, crate::host_record_bootstrap::Bootstrap>>,
    plane_cleanup: Mutex<Vec<std::sync::Weak<crate::plane_driver::PlaneDriver>>>,
    records: Option<Records>,
    persistence: Option<Arc<crate::persistence::facade::CoreStore>>,
    native_claims: NativeClaims,
    pool: Option<Arc<dyn Offload>>,
    pending: Arc<PendingRecords>,
    units: Arc<crate::host_units::UnitRecords>,
    batcher: Arc<WriteBehind>,

    chains: Arc<crate::host_chains::ChainBook>,
    signer: Option<Arc<dyn SignKey>>,
    trust: Arc<TrustBook>,

    trust_resync: Arc<(std::sync::atomic::AtomicU64, std::sync::atomic::AtomicBool)>,
    /// Store upkeep jobs admitted to the pool and not yet finished or dropped unrun: `drain`
    /// certifies nothing while one is outstanding.
    upkeep: Arc<std::sync::atomic::AtomicUsize>,

    judge: Option<Arc<dyn DestJudge>>,
    demotions: Option<Demotions>,

    work: Arc<WorkBook>,
    recovery: recovery_runtime::RecoveryRuntime,
    work_bounds: WorkBounds,

    bounds_of: Mutex<HashMap<Arc<str>, WorkBounds>>,

    standing: Option<Standing>,
    nested: Arc<crate::pump::NestedPool>,

    disk: Arc<crate::host_disk::DiskLane>,

    sessions: crate::channels::line_carriers::LineCarriers,

    verify: crate::host_verify::VerifyBook,

    credentials: Option<Arc<dyn CredentialRead>>,

    tickets: Option<Arc<dyn TicketPress>>,
}

/// All policy and I/O dependencies supplied by the S7 composition root.
/// Optional signing and ticket services represent configured absence, never deferred wiring.
pub struct CoreServicesInputs {
    pub persistence: Arc<crate::persistence::facade::CoreStore>,
    pub pool: Arc<dyn Offload>,
    pub signer: Option<Arc<dyn SignKey>>,
    pub demotions: Arc<DemotionRecord>,
    pub demotion_owner: Option<Arc<str>>,
    pub tickets: Option<Arc<dyn TicketPress>>,
    pub standing: Standing,
    pub judge: Arc<dyn DestJudge>,
    pub credentials: Arc<dyn CredentialRead>,
    pub disk: Arc<crate::host_disk::DiskLane>,
}

pub use crate::channels::line_carriers::CarrierSink;

pub(crate) const SESSION_EMIT_ACTION: &str = "session.emit";

pub(crate) const SESSION_NOT_OPEN: &str = "no such carrier session is open for this instance";

/// ONE DECISION ATTEMPT, as either path builds it (r3 §4.2). Request context is captured here, at
/// build time, because the durable write may run on the host pool (condition B-C2).
pub(crate) struct DecisionAttempt {
    pub(crate) instance: String,
    pub(crate) counterparty: String,
    pub(crate) item: Option<String>,
    pub(crate) ruling: Ruling,
    /// The reviewed digest as text for the audit row; `None` = the plane path's unconditional revoke.
    pub(crate) reviewed: Option<Option<String>>,
    pub(crate) actor: DecidedBy,
    pub(crate) operation: Option<String>,
    pub(crate) request_id: Option<String>,
    /// The route the decision arrived on: the audit row's `resource`.
    pub(crate) resource: String,
}

/// What one decision attempt came to, and whether its typed audit row was written (r3 §5.2).
#[derive(Debug)]
pub struct Decided {
    pub result: Result<KeyRow, TrustRefused>,
    /// The typed trust row was emitted for this attempt (the host-side flag, condition A-C4b).
    pub audited: bool,
}

struct TrustDecision {
    permit: crate::trust::book::DecisionPermit,
    fact: crate::trust::book::RulingRow,
    record: Arc<DemotionRecord>,
    clear: Vec<String>,
}
impl TrustDecision {
    async fn finish(self) -> Result<KeyRow, TrustRefused> {
        match self
            .record
            .keep_decision_attempt(&self.fact, &self.clear)
            .await
        {
            Ok(()) => self.permit.apply(&self.fact).map_err(trust_refused),
            Err(WriteFailure::Earlier(_)) => Err(TrustRefused::Earlier),
            Err(WriteFailure::NotApplied(why)) => Err(TrustRefused::Store(why)),
            Err(WriteFailure::Unknown { op_id }) => Err(TrustRefused::Unknown {
                op_id,
                decided_at: self.fact.decided_at.unwrap_or_default(),
            }),
        }
    }
}

/// Step 7: the one typed trust row for this attempt, whatever it came to (r3 §5.2).
fn audit_decision(
    attempt: &DecisionAttempt,
    key: &str,
    result: Result<KeyRow, TrustRefused>,
    at_ms: u64,
) -> Decided {
    let (outcome, reason) = decision_outcome(&result);
    let action = match attempt.ruling {
        Ruling::Approve => "trust_approve",
        Ruling::Revoke => "trust_revoke",
    };
    let (decided_at, op_id) = match &result {
        Err(TrustRefused::Unknown { op_id, decided_at }) => {
            (Some(*decided_at), Some(hex::encode(op_id)))
        }
        _ => (None, None),
    };
    let data = busbar_contract::json::json!({
        "key": key,
        "instance": attempt.instance,
        "counterparty": attempt.counterparty,
        "item": attempt.item,
        "ruling": action,
        "reviewed": attempt.reviewed,
        "approved": result.as_ref().ok().and_then(|row| row.approved.clone()),
        "decided_by": attempt.actor,
        "decided_at": decided_at,
        "attempt": op_id,
        "reason": reason,
    });
    crate::audit_ring::AUDIT.record_row_at(
        trust_audit_row(
            action,
            &attempt.resource,
            outcome,
            &attempt.actor,
            attempt.request_id.clone(),
            attempt.operation.clone(),
            &data,
        ),
        at_ms,
    );
    Decided {
        result,
        audited: true,
    }
}

/// The audit `outcome` and `reason` of one attempt's result.
fn decision_outcome(result: &Result<KeyRow, TrustRefused>) -> (&'static str, &'static str) {
    use crate::audit_ring::{OUTCOME_APPLIED, OUTCOME_DEGRADED, OUTCOME_REJECTED};
    match result {
        Ok(_) => (OUTCOME_APPLIED, ""),
        Err(TrustRefused::Unknown { .. }) => (OUTCOME_DEGRADED, "outcome_unknown"),
        Err(why) => (OUTCOME_REJECTED, why.reason()),
    }
}

/// The typed trust audit row (r3 §5.2): fixed members only, never pin material.
fn trust_audit_row(
    action: &str,
    resource: &str,
    outcome: &str,
    actor: &DecidedBy,
    request_id: Option<String>,
    operation: Option<String>,
    data: &busbar_contract::json::Value,
) -> crate::audit::auditlog::AuditRowInput {
    crate::audit::auditlog::AuditRowInput {
        action: action.to_string(),
        resource: resource.to_string(),
        outcome: outcome.to_string(),
        principal: actor.principal().to_string(),
        request_id,
        idempotency_key: operation,
        kind: Some("core".to_string()),
        instance: Some("trust".to_string()),
        data: busbar_contract::json::to_string(data)
            .ok()
            .and_then(|text| crate::audit_ring::AuditData::from_json(&text).ok())
            .unwrap_or_default(),
        ..Default::default()
    }
}

fn trust_key(instance: &str, counterparty: &str, item: Option<&str>) -> String {
    match item {
        Some(item) => format!("{instance}/{counterparty}/{item}"),
        None => format!("{instance}/{counterparty}"),
    }
}

/// Emit the kernel's own trust event (a drift demotion, a quarantine or its clear) as a typed row
/// with `principal = kernel` (r3 §5.2, condition B-C3). Request context is `None`: kernel events
/// carry none (condition B-C2).
fn kernel_trust_row(
    action: &str,
    (instance, counterparty, item): (&str, &str, Option<&str>),
    outcome: &'static str,
    reason: &str,
    at_ms: u64,
) {
    let data = busbar_contract::json::json!({
        "key": trust_key(instance, counterparty, item),
        "instance": instance,
        "counterparty": counterparty,
        "item": item,
        "decided_by": DecidedBy::Kernel,
        "reason": reason,
    });
    crate::audit_ring::AUDIT.record_row_at(
        trust_audit_row(
            action,
            "kernel:trust",
            outcome,
            &DecidedBy::Kernel,
            None,
            None,
            &data,
        ),
        at_ms,
    );
}
fn trust_refused(why: Undecided) -> TrustRefused {
    match why {
        Undecided::NoSuchKey => TrustRefused::NoSuchKey,
        Undecided::NothingSighted => TrustRefused::NothingSighted,
        Undecided::Rootless => TrustRefused::Rootless,
        Undecided::Stale => TrustRefused::Stale,
        Undecided::InProgress => TrustRefused::InProgress,
        Undecided::Unverified => TrustRefused::Unverified,
    }
}
fn trust_decision_answer(result: Result<KeyRow, TrustRefused>) -> Stored {
    Stored::ready(match result {
        Ok(row) => decided_code(row.state),
        Err(TrustRefused::NoSuchKey | TrustRefused::Ambiguous) => svc::UNDECIDED_UNKNOWN,
        Err(TrustRefused::NothingSighted | TrustRefused::Unverified) => svc::UNDECIDED_UNPINNED,
        Err(TrustRefused::Stale) => svc::UNDECIDED_STALE,
        Err(TrustRefused::Rootless) => svc::UNDECIDED_ROOTLESS,
        Err(TrustRefused::Store(_) | TrustRefused::Unknown { .. }) => {
            return failed(DECISION_UNKEPT)
        }
        Err(TrustRefused::Unavailable) => return failed(DECISION_UNKEPT),
        Err(TrustRefused::Earlier | TrustRefused::InProgress) => svc::UNDECIDED_STALE,
    })
}

struct Demotions {
    record: Arc<DemotionRecord>,
    default_instance: Option<Arc<str>>,
}

struct TrustResync(Arc<(std::sync::atomic::AtomicU64, std::sync::atomic::AtomicBool)>);

impl Drop for TrustResync {
    fn drop(&mut self) {
        let (_, running) = &*self.0;
        running.store(false, std::sync::atomic::Ordering::Release);
    }
}

/// One admitted Store upkeep job, counted from its admission to the pool until it finishes or
/// is dropped unrun, so a record drain never certifies an empty queue while it is outstanding.
struct Upkeep(Arc<std::sync::atomic::AtomicUsize>);

impl Upkeep {
    fn admit(count: &Arc<std::sync::atomic::AtomicUsize>) -> Self {
        count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self(Arc::clone(count))
    }
}

impl Drop for Upkeep {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
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
    pub fn from_inputs(inputs: CoreServicesInputs) -> Self {
        Self {
            observations: observations_runtime::ObservationRuntime::default(),
            origin: crate::off_path::host_services::boot_instant(),
            wall_ms: Arc::new(crate::store::now_ms),
            mono_ns: None,
            instances: Mutex::default(),
            native_invocations: Mutex::default(),
            trust_decisions: Mutex::default(),
            record_bootstrap: Mutex::default(),
            native_record_bootstrap: Mutex::default(),
            plane_cleanup: Mutex::default(),
            records: None,
            persistence: Some(inputs.persistence),
            native_claims: Arc::default(),
            pool: Some(inputs.pool),
            pending: Arc::default(),
            units: Arc::default(),
            batcher: Arc::default(),
            chains: Arc::default(),
            signer: inputs.signer,
            trust: Arc::default(),
            trust_resync: Arc::default(),
            upkeep: Arc::default(),
            judge: Some(inputs.judge),
            demotions: Some(Demotions {
                record: inputs.demotions,
                default_instance: inputs.demotion_owner,
            }),
            work: Arc::default(),
            recovery: recovery_runtime::RecoveryRuntime::default(),
            work_bounds: WorkBounds::default(),
            bounds_of: Mutex::default(),
            standing: Some(inputs.standing),
            nested: Arc::new(crate::pump::NestedPool::new(
                NEST_CONCURRENCY,
                NEST_DEPTH_MAX as usize + 1,
            )),
            disk: inputs.disk,
            sessions: crate::channels::line_carriers::LineCarriers::new(),
            verify: crate::host_verify::VerifyBook::default(),
            outbound: crate::host_outbound::Custody::default(),
            credentials: Some(inputs.credentials),
            tickets: inputs.tickets,
        }
    }

    #[must_use]
    pub fn new() -> Self {
        Self {
            observations: observations_runtime::ObservationRuntime::default(),
            origin: crate::off_path::host_services::boot_instant(),
            wall_ms: Arc::new(crate::store::now_ms),
            mono_ns: None,
            instances: Mutex::default(),
            native_invocations: Mutex::default(),
            trust_decisions: Mutex::default(),
            record_bootstrap: Mutex::default(),
            native_record_bootstrap: Mutex::default(),
            plane_cleanup: Mutex::default(),
            records: None,
            persistence: None,
            native_claims: Arc::default(),
            pool: None,
            pending: Arc::default(),
            units: Arc::default(),
            batcher: Arc::default(),
            chains: Arc::default(),
            signer: None,
            trust: Arc::default(),
            trust_resync: Arc::default(),
            upkeep: Arc::default(),
            judge: None,
            demotions: None,
            work: Arc::default(),
            recovery: recovery_runtime::RecoveryRuntime::default(),
            work_bounds: WorkBounds::default(),
            bounds_of: Mutex::default(),
            standing: None,
            nested: Arc::new(crate::pump::NestedPool::new(
                NEST_CONCURRENCY,
                NEST_DEPTH_MAX as usize + 1,
            )),
            disk: Arc::default(),
            sessions: crate::channels::line_carriers::LineCarriers::new(),
            verify: crate::host_verify::VerifyBook::default(),
            outbound: crate::host_outbound::Custody::default(),
            credentials: None,
            tickets: None,
        }
    }

    /// Only the core's gated admin dispatcher lends this scoped authority. It is
    /// bound to the opened caller, live ticket and configured counterparty.
    pub(crate) fn grant_trust_decision(
        &self,
        caller: &Caller,
        ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        counterparty: &str,
        authority: TrustDecisionAuthority,
    ) -> Option<TrustDecisionGrant<'_>> {
        if caller.kind() != busbar_contract::abi::mechanism::KindCode::Plane || ticket.is_none() {
            return None;
        }
        let facts = self.facts(caller)?;
        let index = facts
            .trust
            .iter()
            .position(|(name, _)| name == counterparty)?;
        let key = (caller.incarnation().clone(), ticket);
        let mut grants = self
            .trust_decisions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if grants.contains_key(&key) {
            return None;
        }
        grants.insert(
            key.clone(),
            GrantedCounterparty {
                facts,
                index,
                authority,
                request_id: crate::admin::gate::request_id_in_scope(),
            },
        );
        Some(TrustDecisionGrant {
            services: self,
            key,
        })
    }

    /// Install an operator-attested cold migration grant before ANY instance admission. The
    /// attached store is immutable for this KernelServices lifetime. Never call from reload.
    /// Blocking: the composition root invokes this on its blocking pool before serving planes.
    pub async fn arm_record_bootstrap(
        &self,
        receipt: crate::host_record_bootstrap::ColdRecordReceipt,
        expected_store_fingerprint: &str,
        resolve_witness: impl Fn(
            &str,
            &[u8],
            &[u8],
        ) -> Result<busbar_contract::persistence::Address, &'static str>,
    ) -> Result<(), &'static str> {
        {
            let instances = self.lock_instances();
            let bootstrap = self
                .record_bootstrap
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if !instances.is_empty()
                || bootstrap.is_some()
                || !self.batcher.idle()
                || self.pending.queued() != 0
            {
                return Err("record bootstrap requires a cold, unadmitted host");
            }
        }
        let store = self.persistence.as_ref().ok_or(NO_STORE)?;
        let grant = crate::host_record_bootstrap::Bootstrap::consume(
            receipt,
            expected_store_fingerprint,
            store,
            resolve_witness,
        )
        .await?;
        // No admission lock crosses native I/O. Recheck atomically before
        // publishing; a concurrent admission consumes no bootstrap authority.
        let instances = self.lock_instances();
        let mut bootstrap = self
            .record_bootstrap
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !instances.is_empty()
            || bootstrap.is_some()
            || !self.batcher.idle()
            || self.pending.queued() != 0
        {
            return Err("record bootstrap ceased to be cold before publication");
        }
        tracing::info!(instance=%grant.instance,epoch=%grant.epoch,"consumed operator-attested cold record bootstrap receipt");
        *bootstrap = Some(grant);
        Ok(())
    }

    /// Bind the actual loader caller before admitting the cold migration namespace. Only the
    /// composition root calls this Rust-only method; service callers cannot choose their identity.
    pub fn bind_record_bootstrap_caller(&self, caller: &Caller) -> Result<(), &'static str> {
        let instances = self.lock_instances();
        let mut held = self
            .record_bootstrap
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(grant) = held
            .as_mut()
            .filter(|grant| grant.instance == caller.namespace().as_ref())
        else {
            return Ok(());
        };
        if instances.contains_key(caller.namespace()) {
            return Err("cold bootstrap namespace is already admitted");
        }
        grant.bind_caller(caller)
    }

    #[must_use]
    pub fn ticket_prefix_of(&self, instance: &str) -> Option<String> {
        let instances = self.lock_instances();
        let facts = instances.get(instance)?;
        crate::off_path::host_services::ticket_prefix(facts)
    }

    /// Open a carrier session serving as `principal`: the line's own shared name, held by the
    /// session for its life and not copied. Runs once as a carrier line opens.
    pub fn open_carrier_session(
        &self,
        caller: &Caller,
        principal: &Arc<str>,
        sink: CarrierSink,
    ) -> u64 {
        self.sessions
            .open(caller.incarnation(), Arc::clone(principal), sink)
            .get()
    }

    pub fn close_carrier_session(&self, session: u64) {
        self.sessions.end(session);
    }

    /// The line carriers (IF §12.23): a plane's `PlaneOut::Emit` goes through `emit_from_plane`.
    #[must_use]
    pub fn line_carriers(&self) -> &crate::channels::line_carriers::LineCarriers {
        &self.sessions
    }

    fn dispatch_child(
        &self,
        context: InvocationContext,
        route: &Arc<dyn NestRoute>,
        nest: Nest,
        done: NestDone,
    ) {
        let permit = match self.nested.enter(nest.depth as usize) {
            Ok(permit) => permit,
            Err(busbar_contract::caps::ReasonCode::InFlightCap) => {
                done(NestReply::Unserved(NEST_FULL));
                return;
            }
            Err(_) => {
                done(NestReply::Unserved(NEST_TOO_DEEP));
                return;
            }
        };
        let pool = self.nested.clone();
        struct Held {
            pool: Arc<crate::pump::NestedPool>,
            permit: Option<crate::pump::NestedPermit>,
            done: Option<NestDone>,
        }
        impl Drop for Held {
            fn drop(&mut self) {
                if let Some(permit) = self.permit.take() {
                    self.pool.leave(permit);
                }
                if let Some(done) = self.done.take() {
                    done(NestReply::Failed(NEST_DROPPED));
                }
            }
        }
        impl Held {
            fn answer(mut self, answer: NestReply) {
                if let Some(done) = self.done.take() {
                    done(answer);
                }
            }
        }
        let held = Held {
            pool,
            permit: Some(permit),
            done: Some(done),
        };
        let retained = context.clone();
        route.nest(
            context,
            nest,
            Box::new(move |answer| {
                let _context = retained;
                held.answer(answer);
            }),
        );
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

    /// Set `instance`'s work bounds, keyed by the caller's own shared label. Runs as an instance
    /// is admitted (boot, reload).
    pub fn bound_work(&self, instance: &Arc<str>, bounds: WorkBounds) {
        self.bounds_of
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(Arc::clone(instance), bounds);
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

    /// The destination judge this host runs `dest.judge` under, if one is installed: the plane port's JUDGE
    /// intents ask the same guard.
    #[must_use]
    pub fn installed_dest_judge(&self) -> Option<Arc<dyn DestJudge>> {
        self.judge.clone()
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
    pub fn with_records(mut self, reads: Arc<dyn RecordRows>) -> Self {
        self.records = Some(Records { reads });
        self
    }

    /// Supply persistence while the service is still exclusively owned.
    #[must_use]
    pub fn with_persistence(mut self, store: Arc<crate::persistence::facade::CoreStore>) -> Self {
        self.persistence = Some(store);
        self
    }

    #[must_use]
    pub fn with_standing(mut self, standing: Standing) -> Self {
        self.standing = Some(standing);
        self
    }

    #[must_use]
    pub fn with_tickets(mut self, tickets: Arc<dyn TicketPress>) -> Self {
        self.tickets = Some(tickets);
        self
    }

    pub fn native_first_start(&self) -> Option<Arc<crate::persistence::first_start::FirstStart>> {
        self.persistence
            .as_ref()
            .and_then(|store| store.first_start())
    }

    /// Only the selected initial caller may initialize records during READY. Native
    /// ownership, not an empty scan or a principal grant, supplies this finite authority.
    pub async fn bind_native_record_bootstrap(&self, caller: &Caller) -> Result<(), &'static str> {
        let Some(proof) = self.native_first_start() else {
            return Ok(());
        };
        if proof.published().await {
            return Ok(());
        }
        let Some(grant) = crate::host_record_bootstrap::Bootstrap::native(&proof, caller).await?
        else {
            return Ok(());
        };
        let mut grants = self
            .native_record_bootstrap
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if grants.contains_key(caller.namespace().as_ref()) {
            return Err("native record bootstrap caller already bound");
        }
        grants.insert(Arc::clone(caller.namespace()), grant);
        Ok(())
    }

    pub fn revoke_native_record_bootstrap(&self, caller: &Caller) -> Result<(), &'static str> {
        let mut grants = self
            .native_record_bootstrap
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if grants
            .get(caller.namespace().as_ref())
            .is_some_and(|grant| !grant.native_accepts(caller))
        {
            return Err("native record bootstrap caller changed");
        }
        grants.remove(caller.namespace().as_ref());
        Ok(())
    }

    fn native_work_writer(&self, caller: &Caller) -> Result<Option<NativeWorkWriter>, Stored> {
        let Some(store) = self.persistence.as_ref() else {
            return Ok(None);
        };
        if self.facts(caller).is_none() {
            return Err(Stored::refused(NOT_ADMITTED));
        }
        let pool = self
            .pool
            .as_ref()
            .cloned()
            .ok_or_else(|| Stored::refused(NO_POOL))?;
        Ok(Some(NativeWorkWriter {
            instance: Arc::clone(caller.namespace()),
            store: Arc::clone(store),
            batcher: Arc::clone(&self.batcher),
            pending: Arc::clone(&self.pending),
            chains: Arc::clone(&self.chains),
            pool,
        }))
    }

    fn native_records(
        &self,
        caller: &Caller,
        kind: &str,
    ) -> Result<Option<NativeRecordScope>, Stored> {
        let Some(store) = self.persistence.as_ref() else {
            return Ok(None);
        };
        let facts = self
            .facts(caller)
            .ok_or_else(|| Stored::refused(NOT_ADMITTED))?;
        let Some(schema) = facts
            .record_kinds
            .iter()
            .find(|schema| schema.as_str() == kind)
            .copied()
        else {
            return Err(Stored::refused(NOT_A_KIND));
        };
        let rows = crate::host_records_async::AsyncRecords::authorized(
            Arc::clone(store),
            caller.namespace(),
            facts
                .record_kinds
                .iter()
                .map(|schema| schema.as_str())
                .chain(std::iter::once(
                    crate::host_chains::CHAIN_LIFE_SCHEMA.as_str(),
                )),
        );
        rows.map(|rows| {
            Some(NativeRecordScope {
                rows,
                facts,
                schema,
            })
        })
        .map_err(|_| failed(STORE_FAILED))
    }

    #[must_use]
    pub fn with_pool(mut self, pool: Arc<dyn Offload>) -> Self {
        self.pool = Some(pool);
        self
    }

    #[must_use]
    pub fn with_signer(mut self, signer: Arc<dyn SignKey>) -> Self {
        self.signer = Some(signer);
        self
    }

    #[must_use]
    pub fn with_demotions(
        mut self,
        demotions: Arc<DemotionRecord>,
        default_instance: &str,
    ) -> Self {
        self.demotions = Some(Demotions {
            record: demotions,
            default_instance: Some(crate::off_path::host_services::intern(default_instance)),
        });
        self
    }

    fn pool(&self) -> Option<&dyn Offload> {
        self.pool.as_deref()
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

    /// Admit `label`'s declared facts. Runs when a plane instance is admitted (boot, reload),
    /// never on a request. The label is the caller's own shared one: it keys the instance here
    /// and names it in a refusal, and is copied for neither.
    pub async fn admit(&self, label: &Arc<str>, facts: InstanceFacts) -> Result<(), AdmitRefused> {
        let instance: &str = label;
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
                instance: Arc::clone(label),
                kind: kind.as_str(),
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
        let mut conditional_kinds = foldhash::HashSet::default();
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
        let key = Arc::clone(label);

        let (snapshot, default) = match self.demotions.as_ref() {
            Some(d) => (
                Some(d.record.snapshot().await.map_err(trust_unread)?),
                d.default_instance.as_deref() == Some(instance),
            ),
            None => (None, false),
        };
        let (rows, decided) = snapshot.map_or_else(
            || (Vec::new(), Vec::new()),
            |snapshot| (snapshot.demotions, snapshot.decisions),
        );
        let mut instances = self.lock_instances();
        if self
            .native_record_bootstrap
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(instance)
            && instances.contains_key(instance)
        {
            return Err(AdmitRefused::BootstrapHeld {
                instance: Arc::clone(label),
            });
        }
        if self
            .record_bootstrap
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|grant| {
                grant.instance == instance && (instances.contains_key(instance) || !grant.bound())
            })
        {
            return Err(AdmitRefused::BootstrapHeld {
                instance: Arc::clone(label),
            });
        }
        let decided = if instances.contains_key(instance) {
            Vec::new()
        } else {
            decided
        };
        let domain_holder = facts.signing.as_ref().and_then(|declared| {
            instances
                .iter()
                .find(|(held, f)| {
                    &***held != instance
                        && f.signing
                            .as_ref()
                            .is_some_and(|s| s.domain == declared.domain)
                })
                .map(|(held_by, _)| Arc::clone(held_by))
        });
        if let Some(held_by) = domain_holder {
            // The refused declaration is dropped with this refusal: its domain is moved out of
            // it into the refusal, not copied.
            return Err(AdmitRefused::DomainHeld {
                domain: facts.signing.map(|s| s.domain).unwrap_or_default(),
                held_by,
                asked_by: Arc::clone(label),
            });
        }
        if let Some(prefix) = instances
            .get(instance)
            .and_then(|f| f.ticket_prefix.as_ref())
        {
            if facts.ticket_prefix.as_ref() != Some(prefix) {
                // The admitted prefix stays with the admitted instance: the refusal names it in
                // one copy of its own.
                return Err(AdmitRefused::TicketPrefixChanged {
                    instance: Arc::clone(label),
                    prefix: prefix.clone(),
                });
            }
        }
        let prefix_holder = facts.ticket_prefix.as_ref().and_then(|prefix| {
            instances
                .iter()
                .find(|(held, f)| &***held != instance && f.ticket_prefix.as_ref() == Some(prefix))
                .map(|(held_by, _)| Arc::clone(held_by))
        });
        if let Some(held_by) = prefix_holder {
            // As the domain above: the refused declaration's own prefix, moved out of it.
            return Err(AdmitRefused::TicketPrefixHeld {
                prefix: facts.ticket_prefix.unwrap_or_default(),
                held_by,
                asked_by: Arc::clone(label),
            });
        }
        let prefix = demotion_key(instance, "");
        if let Some(store) = self.persistence.as_ref() {
            for schema in &facts.record_kinds {
                store
                    .register_claim_scope(instance, schema.as_str())
                    .map_err(|_| AdmitRefused::ClaimMaintenance {
                        kind: schema.as_str(),
                    })?;
            }
        }
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

    /// Every admitted counterparty's trust facts (r3 §3.4 `subjects`).
    #[must_use]
    pub fn trust_counterparties(&self) -> Vec<crate::trust::book::CounterpartyFacts> {
        self.trust.counterparties()
    }

    /// Whether the live standing re-check is attached (r3 §3.4 `state.standing.attached`).
    #[must_use]
    pub fn standing_attached(&self) -> bool {
        self.standing.is_some()
    }

    /// THE DECISION CUSTODY (r3 §4.2 step 1): the durable decision record, only when it is present
    /// and bound to a Store. Without it no decision can be kept, so none is made.
    #[must_use]
    pub fn trust_decision_record(&self) -> Option<Arc<DemotionRecord>> {
        self.demotions
            .as_ref()
            .filter(|d| d.record.bound())
            .map(|d| Arc::clone(&d.record))
    }

    /// THE ADMIN DECISION (`POST /trust/approve|revoke`, r3 §4.1–§4.2). `reviewed` is what the
    /// operator reviewed; there is no key-only path. Exactly one typed audit row is written for
    /// every call (r3 §5.2), and [`Decided::audited`] says so.
    pub async fn trust_rule_by(
        &self,
        key: &str,
        ruling: Ruling,
        reviewed: Reviewed<'_>,
        actor: &str,
        operation: Option<&str>,
    ) -> Decided {
        // The decision's one reading of the host clock: its stamp and its audit row's.
        let at_ms = (self.wall_ms)();
        let resource = match ruling {
            Ruling::Approve => "/api/v1/admin/trust/approve",
            Ruling::Revoke => "/api/v1/admin/trust/revoke",
        };
        let mut attempt = DecisionAttempt {
            instance: String::new(),
            counterparty: String::new(),
            item: None,
            ruling,
            reviewed: Some(match reviewed {
                Reviewed::Seen(digest) => Some(digest.to_string()),
                Reviewed::Unsighted => None,
            }),
            actor: DecidedBy::Principal {
                id: actor.to_string(),
            },
            operation: operation.map(str::to_string),
            request_id: crate::admin::gate::request_id_in_scope(),
            resource: resource.to_string(),
        };
        // Step 1 before any book access: custody is process-global, so a refusal here says nothing
        // about any key.
        let Some(record) = self.trust_decision_record() else {
            return audit_decision(&attempt, key, Err(TrustRefused::Unavailable), at_ms);
        };
        // Step 2: a flattened key must name exactly one row; the first of two matches would let an
        // upstream choose the row by naming a tool.
        let mut matching = self.trust.rows().into_iter().filter(|r| r.key() == key);
        let Some(found) = matching.next() else {
            return audit_decision(&attempt, key, Err(TrustRefused::NoSuchKey), at_ms);
        };
        if matching.next().is_some() {
            return audit_decision(&attempt, key, Err(TrustRefused::Ambiguous), at_ms);
        }
        attempt.instance = found.instance;
        attempt.counterparty = found.counterparty;
        attempt.item = found.item;
        let result = match self.prepare_decision(&attempt, Some(reviewed), record, at_ms) {
            Ok(decision) => decision.finish().await,
            Err(why) => Err(why),
        };
        audit_decision(&attempt, key, result, at_ms)
    }

    /// Steps 3–4: the permit, the review check under it, and the stamp.
    fn prepare_decision(
        &self,
        attempt: &DecisionAttempt,
        reviewed: Option<Reviewed<'_>>,
        record: Arc<DemotionRecord>,
        at_ms: u64,
    ) -> Result<TrustDecision, TrustRefused> {
        let (instance, counterparty, item) = (
            attempt.instance.as_str(),
            attempt.counterparty.as_str(),
            attempt.item.as_deref(),
        );
        let permit = self
            .trust
            .begin_decision(instance, counterparty, item)
            .map_err(trust_refused)?;
        let mut fact = self
            .trust
            .rule(instance, counterparty, item, attempt.ruling, reviewed)
            .map_err(trust_refused)?;
        fact.decided_by = Some(attempt.actor.clone());
        fact.decided_at = Some(at_ms / 1000);
        fact.operation.clone_from(&attempt.operation);
        let clear = if fact.item.is_none() && attempt.ruling == Ruling::Approve {
            let default = self
                .demotions
                .as_ref()
                .is_some_and(|d| d.default_instance.as_deref() == Some(fact.instance.as_ref()));
            crate::off_path::host_services::decision_clears(
                &fact.instance,
                &fact.counterparty,
                default,
            )
        } else {
            Vec::new()
        };
        Ok(TrustDecision {
            permit,
            fact,
            clear,
            record,
        })
    }

    /// RESOLVE AN UNKNOWN DECISION on a same-key replay (r3 §4.6, conditions B-C5 and A-C4a). It
    /// plans no new decision: it asks the record what its own settlement proves about the attempt,
    /// and answers `Applied` only once the kept row is in force in this node's book.
    pub async fn trust_resolve_attempt(
        &self,
        op_id: [u8; 16],
        key: &str,
        decided_at: u64,
        operation: Option<&str>,
    ) -> Resolution {
        let Some(record) = self.trust_decision_record() else {
            return Resolution::Unknown;
        };
        match record.attempt_verdict(op_id).await {
            Verdict::NotApplied => return Resolution::NotApplied,
            Verdict::Landed | Verdict::Unknown => {}
        }
        let Ok(kept) = record.kept().await else {
            return Resolution::Unknown;
        };
        let Some(row) = kept.decisions.into_iter().find(|row| {
            trust_key(&row.instance, &row.counterparty, row.item.as_deref()) == key
                && row.decided_at == Some(decided_at)
                && row.operation.as_deref() == operation
                && !row.demoted
        }) else {
            return Resolution::Unknown;
        };
        let snapshot = self.trust.decision_snapshot();
        self.trust
            .resync_decided(&snapshot, std::slice::from_ref(&row));
        let in_force = self.trust.rows().into_iter().find(|current| {
            current.key() == key
                && match &row.approved {
                    Some(at) => {
                        current.approved.as_ref() == Some(at) && current.state != KeyState::New
                    }
                    None => current.state == KeyState::New,
                }
        });
        in_force.map_or(Resolution::Unknown, Resolution::Applied)
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
        // Reserve the WHOLE kind before ordinary principal scopes, including malformed suffixes.
        if target
            .split_once(':')
            .is_some_and(|(kind, _)| kind == "record-quota-bootstrap")
        {
            return target == crate::host_record_bootstrap::ENTITLEMENT
                && (self
                    .record_bootstrap
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .is_some_and(|grant| grant.instance == caller.namespace().as_ref())
                    || self
                        .native_record_bootstrap
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(caller.namespace().as_ref())
                        .is_some_and(|grant| grant.native_accepts(caller)));
        }
        if target == "standing:" {
            return self.stands(unit);
        }
        let Some((kind, name)) = target.split_once(':') else {
            return false;
        };
        if !facts.scope_kinds.iter().any(|k| k == kind) {
            crate::diagnostics::diag_debug!(
                crate::diagnostics::ENTITLEMENT_UNDECLARED_SCOPE_KIND,
                instance = %caller.namespace(),
                scope_kind = %kind,
                "an entitlement check named a scope kind this plane does not declare"
            );
            return false;
        }
        let Some(record) = unit.and_then(|u| self.units.get(u)) else {
            return false;
        };
        let now = (self.wall_ms)() / 1000;

        let principal = match (record.principal.as_ref(), self.standing.as_ref()) {
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
        match (record.principal.as_ref(), self.standing.as_ref()) {
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
        let native = self.persistence.as_ref();
        let native_facts = if native.is_some() {
            Some(self.facts(caller).ok_or(NOT_ADMITTED)?)
        } else {
            None
        };
        let (schema, records, pool) = if let Some(facts) = native_facts.as_ref() {
            let schema = facts
                .record_kinds
                .iter()
                .find(|schema| schema.as_str() == kind)
                .copied()
                .ok_or(NOT_A_KIND)?;
            (schema, None, self.pool().ok_or(NO_POOL)?)
        } else {
            let (schema, records, pool) =
                self.scope(caller, kind).map_err(|stored| stored.error)?;
            (schema, Some(records), pool)
        };
        let conditional = if let Some(facts) = native_facts.as_ref() {
            facts.conditional_record_kinds.iter().any(|index| {
                facts
                    .record_kinds
                    .get(*index as usize)
                    .is_some_and(|schema| schema.as_str() == kind)
            })
        } else {
            self.conditional_kind(caller.namespace(), kind)
        };
        if conditional {
            return Err("this record kind requires conditional publication");
        }
        let chain = if let Some(facts) = native_facts.as_ref() {
            Self::chain_of_facts(facts, kind)
        } else {
            self.chain_of(caller, kind)
        };
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
        let make = || {
            // A write laid on the overlay shares its bytes with its overlay row: they are not
            // copied for it. A chained write has no overlay row and keeps its bytes as they came.
            let (seq, value) = match chain {
                Some(_) => (0, crate::host_records::WriteBytes::Own(value)),
                None => {
                    let shared = Arc::new(value);
                    let seq = pending.enqueue(caller.namespace(), schema.as_str(), key, &shared);
                    (seq, crate::host_records::WriteBytes::Shared(shared))
                }
            };
            let key = key.to_vec();
            Write {
                instance: Arc::clone(caller.namespace()),
                schema,
                key,
                value,
                seq,
                owed: WriteOwed::new(acked),
                chain,
            }
        };
        let started = if native.is_some() {
            self.batcher.push_native_with(make)
        } else {
            self.batcher.push_with(make)
        };
        match started {
            Some(true) => {
                if let Some(store) = native {
                    self.start_native_flush(store, pool)
                } else if let Some(records) = records {
                    self.start_flush(records, pool)
                }
            }
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
        self.persistence.as_ref().is_some()
            || self
                .records
                .as_ref()
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
        let scope =
            crate::host_chains::scope_of(scope).ok_or(crate::host_chains::CHAIN_SCOPE_UNFIT)?;
        let scope = scope.to_string();
        if self.persistence.as_ref().is_some() {
            let rows = self
                .native_records(caller, schema.as_str())
                .map_err(|stored| stored.error)?
                .ok_or(NO_STORE)?;
            let pool = self.pool().ok_or(NO_POOL)?;
            let instance = Arc::clone(caller.namespace());
            let owed = LifeObservationOwed(Some(done));
            pool.run_async(Box::pin(async move {
                owed.answer(
                    crate::host_chains::observe_life_async(&rows.rows, &instance, schema, &scope)
                        .await,
                );
            }));
            return Ok(());
        }
        let records = self.records.as_ref().ok_or(NO_STORE)?;
        let pool = self.pool().ok_or(NO_POOL)?;
        if !records.reads.supports_record_transaction() {
            return Err("record transactions are unsupported");
        }
        let rows = Arc::clone(&records.reads);
        let instance = Arc::clone(caller.namespace());
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
        let candidate = crate::host_chains::CandidateCustody(candidate);
        use crate::host_records::{
            ChainMutation, ConditionalOwed, ConditionalWrite, RecordMutation,
        };
        use busbar_contract::host_records::conditional::{Mutation, Predicate, Request, VERSION};
        let facts = self.facts(caller).ok_or(NOT_A_KIND)?;
        let native = self.persistence.as_ref();
        let records = self.records.as_ref();
        let pool = self.pool().ok_or(NO_POOL)?;
        if native.is_none()
            && !records.is_some_and(|records| records.reads.supports_record_transaction())
        {
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
        // On CoreStore the receipt identity is a held class-M op (DES-264 §4.1): the request's
        // `op_id` is derived from it and the write keeps it until its definitive outcome. A
        // record store plugin dedupes on its own receipts, so it takes a plain kernel op id.
        let held = native
            .map(|store| store.try_record_op())
            .transpose()
            .map_err(|_| QUEUE_FULL)?;
        let mut request = Request {
            version: VERSION,
            op_id: held
                .as_ref()
                .map_or_else(crate::door::op_id, |held| held.op_id()),
            predicates: Vec::new(),
            mutations: Vec::new(),
        };
        for predicate in &candidate.predicates {
            let schema = schema_at(predicate.kind, false)?;
            request.predicates.reserve(1);
            request.predicates.push(Predicate {
                schema: schema.as_str().to_string(),
                key: record_key(caller.namespace(), &predicate.key),
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
                        key: record_key(caller.namespace(), key),
                        value: value.clone(),
                    }
                }
                RecordMutation::Delete { kind, key } => {
                    let schema = schema_at(*kind, false)?;
                    Mutation::Delete {
                        schema: schema.as_str().to_string(),
                        key: record_key(caller.namespace(), key),
                    }
                }
            });
        }
        let mut chains = Vec::<crate::host_chains::ConditionalChain>::new();
        let mut chain_scopes = foldhash::HashMap::default();
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
            let mut action = match chain {
                ChainMutation::Append { content, .. } => {
                    ConditionalChainAction::Append(vec![content.clone()])
                }
                ChainMutation::Drop { .. } => ConditionalChainAction::Drop,
                ChainMutation::Check { .. } => ConditionalChainAction::Check,
            };

            let address = (schema.as_str(), scope);
            if let Some(&index) = chain_scopes.get(&address) {
                let previous: &mut crate::host_chains::ConditionalChain = &mut chains[index];
                if previous.life != *life {
                    return Err("conflicting conditional chain observations");
                }
                match (&mut previous.action, &mut action) {
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
                life: life.clone(),
                action,
            });
        }
        if chains.is_empty() {
            request
                .encode_held()
                .map_err(|_| "invalid record transaction")?;
        }
        let write = ConditionalWrite::new(
            Arc::clone(caller.namespace()),
            request,
            held,
            chains,
            ConditionalOwed::new(candidate.correlation, acked),
            unit,
        );
        match self.batcher.push_conditional(write) {
            Some(true) => {
                if let Some(store) = native {
                    self.start_native_flush(store, pool)
                } else if let Some(records) = records {
                    self.start_flush(records, pool)
                }
            }
            Some(false) => {}
            None => return Err(QUEUE_FULL),
        }
        Ok(())
    }

    fn chain_of(&self, caller: &Caller, kind: &str) -> Option<crate::host_chains::ChainFraming> {
        let facts = self.facts(caller)?;
        Self::chain_of_facts(facts.as_ref(), kind)
    }

    fn chain_of_facts(
        facts: &InstanceFacts,
        kind: &str,
    ) -> Option<crate::host_chains::ChainFraming> {
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

    fn start_native_flush(
        &self,
        store: &Arc<crate::persistence::facade::CoreStore>,
        pool: &dyn Offload,
    ) {
        let unrun = Unrun(Some(Arc::clone(&self.batcher)));
        let pending = Arc::clone(&self.pending);
        let chains = Arc::clone(&self.chains);
        let store = Arc::clone(store);
        pool.run_async(Box::pin(async move {
            if let Some(batcher) = unrun.run() {
                batcher.flush_native(&pending, &store, &chains).await;
            }
        }));
    }

    pub fn flush_tick(&self) {
        if let Some(store) = self.persistence.as_ref() {
            if let Some(pool) = self.pool() {
                if self.batcher.start() {
                    self.start_native_flush(store, pool);
                }
            }
            return;
        }
        if let (Some(records), Some(pool)) = (self.records.as_ref(), self.pool()) {
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
            crate::off_path::host_services::live_planes(&mut registered)
        };
        let mut idle = true;
        for driver in drivers.into_iter().filter_map(|driver| driver.upgrade()) {
            idle &= driver.sweep_with_context(cx);
        }
        idle
    }

    /// Settle dropped callers before final billing flushes, retaining pending work on timeout.
    pub async fn drain_plane_cleanup(&self, deadline: std::time::Duration) -> bool {
        // Sweep until idle, every 2 ms, under the runtime's own timer: no clock is read here.
        let sweep = || std::future::poll_fn(|cx| std::task::Poll::Ready(self.cleanup_planes(cx)));
        let swept = tokio::time::timeout(deadline, async {
            while !sweep().await {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        })
        .await;
        // The deadline passed: one last sweep decides, as the loop's own last pass did.
        match swept {
            Ok(()) => true,
            Err(_) => sweep().await,
        }
    }

    /// Every unit still open in the planes registered for cleanup (every composed plane), read
    /// once at exit for the drain's `open_at_exit` lines (SHUTDOWN-HANG F4).
    pub fn open_unit_evidence(&self) -> Vec<crate::plane_driver::OpenUnitEvidence> {
        let drivers = {
            let mut registered = self.plane_cleanup.lock().unwrap_or_else(|e| e.into_inner());
            crate::off_path::host_services::live_planes(&mut registered)
        };
        crate::off_path::host_services::open_unit_evidence(drivers)
    }

    pub async fn flushes(&self) {
        use futures::StreamExt as _;
        let every = crate::host_records::FLUSH_INTERVAL;
        let mut at = tokio::time::interval(every);
        at.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // A new interval's first tick is immediate: taken here, so the first flush comes one
        // interval after the flusher starts, as before.
        at.tick().await;
        let mut jobs = futures::stream::FuturesUnordered::new();
        loop {
            tokio::select! {
                _ = at.tick() => {
                    std::future::poll_fn(|cx| std::task::Poll::Ready(self.cleanup_planes(cx))).await;
                    self.flush_tick();
                    self.sweep_claims_tick();
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

    /// Advance one registered claim scope through the existing bounded async
    /// host lane. The attachment retains its cursor if this task is cancelled.
    pub(crate) fn sweep_claims_tick(&self) {
        let (Some(store), Some(pool)) = (self.persistence.as_ref(), self.pool()) else {
            return;
        };
        let store = Arc::clone(store);
        let upkeep = Upkeep::admit(&self.upkeep);
        pool.run_async(Box::pin(async move {
            let _upkeep = upkeep;
            if let Err(error) = store.sweep_claim_scope().await {
                tracing::warn!(
                    ?error,
                    "native claim retention maintenance could not advance"
                );
            }
        }));
    }

    pub fn trust_resync_tick(&self) {
        use std::sync::atomic::Ordering;
        let (Some(d), Some(pool)) = (self.demotions.as_ref(), self.pool()) else {
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
        let upkeep = Upkeep::admit(&self.upkeep);
        pool.run_async(Box::pin(async move {
            let (_resync, _upkeep) = (resync, upkeep);
            let snapshot = trust.decision_snapshot();
            match record.decisions().await {
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
        crate::off_path::host_services::drain_until(
            deadline,
            || self.batcher.idle() && self.upkeep.load(std::sync::atomic::Ordering::Acquire) == 0,
            || self.flush_tick(),
        )
    }

    fn lock_instances(&self) -> std::sync::MutexGuard<'_, HashMap<Arc<str>, Arc<InstanceFacts>>> {
        self.instances.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn facts(&self, caller: &Caller) -> Option<Arc<InstanceFacts>> {
        let facts = self.lock_instances().get(caller.namespace()).cloned()?;
        if self
            .native_record_bootstrap
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(caller.namespace().as_ref())
            .is_some_and(|grant| !grant.native_accepts(caller))
        {
            return None;
        }
        if self
            .record_bootstrap
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|grant| !grant.accepts(caller))
        {
            return None;
        }
        Some(facts)
    }

    /// The caller's own standing for `kind`: admitted, and `kind` one it declared.
    fn declared(&self, caller: &Caller, kind: &str) -> Result<RecordSchemaId, Stored> {
        let facts = self
            .facts(caller)
            .ok_or_else(|| Stored::refused(NOT_ADMITTED))?;
        facts
            .record_kinds
            .iter()
            .find(|k| k.as_str() == kind)
            .copied()
            .ok_or_else(|| Stored::refused(NOT_A_KIND))
    }

    fn scope(
        &self,
        caller: &Caller,
        kind: &str,
    ) -> Result<(RecordSchemaId, &Records, &dyn Offload), Stored> {
        let schema = self.declared(caller, kind)?;
        let records = self
            .records
            .as_ref()
            .ok_or_else(|| Stored::refused(NO_STORE))?;
        let pool = self.pool().ok_or_else(|| Stored::refused(NO_POOL))?;
        Ok((schema, records, pool))
    }

    /// The refusal of a record read or claim on a host with no persistence bound.
    fn unbound(&self, caller: &Caller, kind: &str) -> Stored {
        match self.facts(caller) {
            None => Stored::refused(NOT_ADMITTED),
            Some(facts) if !facts.record_kinds.iter().any(|k| k.as_str() == kind) => {
                Stored::refused(NOT_A_KIND)
            }
            Some(_) => Stored::refused(NO_STORE),
        }
    }
}

impl KernelServices {
    fn owner_of_unit(&self, unit: Option<u64>) -> Option<Owner> {
        let record = self.units.get(unit?)?;
        Some(owner_of(record.principal.as_deref().map(|k| k.id.as_str())))
    }

    /// The refusal of a work call on a host with no persistence bound.
    fn work_unbound(&self, caller: &Caller) -> Stored {
        match self.facts(caller) {
            None => Stored::refused(NOT_ADMITTED),
            Some(_) => Stored::refused(NO_STORE),
        }
    }
}

/// A found handle's answer: its state byte as the one item's key, its record as the value, laid
/// straight into the answer's own bytes (the layout [`spans_of`] gives one row).
fn work_found(handle: u64, w: &Work) -> Stored {
    let mut s = Stored::ready(handle);
    s.bytes.reserve_exact(w.record.len().saturating_add(1));
    s.bytes.push(w.state());
    s.bytes.extend_from_slice(&w.record);
    s.spans.push(span(0, 1, 1, w.record.len()));
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

pub(crate) const STORE_FAILED: &str = "the store did not answer";

pub const DECISION_UNKEPT: &str = "the trust decision could not be kept";

const INVALID_TRUST_EVIDENCE: &str = "a trust sighting carries nonblank evidence without NUL";

fn valid_trust_evidence(evidence: &str) -> bool {
    !evidence.trim().is_empty() && !evidence.contains('\0')
}

pub const NO_CREDENTIAL_SOURCE: &str = "no credential source";

pub const NOT_READABLE: &str = "the credential read is not installed yet";

pub const FILL_OUT_OF_RANGE: &str = "a fill asks for 1 to MAX_RANDOM_FILL bytes";

pub(crate) const NO_RANDOMNESS: &str = "the OS randomness source failed";

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
    /// The flattened key names more than one row (an instance or registration name holds `/`).
    Ambiguous,
    /// The key was never sighted (nor declared) at anything to approve.
    NothingSighted,
    /// The counterparty declares no authenticity root: nothing at it can be approved.
    Rootless,
    /// The fingerprint the caller reviewed is not the key's current sighting, or another local
    /// mutation currently owns its durable decision key.
    Stale,
    /// The key's current sighting failed its verification
    /// ([`crate::trust::book::UNVERIFIED_SIGHTING`]): nothing verified to approve.
    Unverified,
    /// The decision could not be kept: the store decided it did not apply. The store's words, for
    /// the node's log.
    Store(String),
    /// Another local decision currently owns this key (r3 §4.5, `decision_in_progress`).
    InProgress,
    /// No bound durable decision record: no decision can be kept (r3 §4.2 step 1).
    Unavailable,
    /// An earlier unsettled write for the same key could not be settled first; nothing was
    /// submitted (r3 §4.4).
    Earlier,
    /// The durable write was submitted and its outcome is unknown; its exact attempt is retained
    /// and may still land (r3 §4.4). `op_id` identifies that attempt for replay resolution.
    Unknown { op_id: [u8; 16], decided_at: u64 },
}

impl TrustRefused {
    /// The closed audit/HTTP reason word for this refusal (r3 §4.5).
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            TrustRefused::NoSuchKey => "unknown_resource",
            TrustRefused::Ambiguous
            | TrustRefused::NothingSighted
            | TrustRefused::Rootless
            | TrustRefused::Unverified => "state_conflict",
            TrustRefused::Stale => "reviewed_digest_stale",
            TrustRefused::Earlier => "action_in_flight",
            TrustRefused::InProgress => "decision_in_progress",
            TrustRefused::Store(_) | TrustRefused::Unavailable => "service_unavailable",
            TrustRefused::Unknown { .. } => "service_unavailable",
        }
    }
}

/// What a same-key replay can say about an earlier unknown decision (r3 §4.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The attempt landed and is now in force in the book: the key's current row.
    Applied(KeyRow),
    /// The store proved the attempt never applied and never can.
    NotApplied,
    /// Nothing proves either; or it landed but is not (yet) in force here.
    Unknown,
}

pub const DEMOTION_SEP: char = '\u{1f}';

#[must_use]
pub fn demotion_key(instance: &str, counterparty: &str) -> String {
    crate::cold::host::services_demotion_key(instance, counterparty)
}

#[must_use]
pub fn claim_token(instance: &str, kind: &str, key: &[u8]) -> String {
    let digest = busbar_contract::crypto::sha256_parts(&[
        instance.as_bytes(),
        &[0],
        kind.as_bytes(),
        &[0],
        key,
    ]);
    let minted = IdempotencyKey::mint(&crate::seal::acquire(), digest);
    hex::encode(minted.bytes())
}

impl HostServices for KernelServices {
    fn usage_observation_output_allowed(
        &self,
        caller: &Caller,
        ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        unit: Option<u64>,
    ) -> bool {
        self.observation_output_allowed(caller, ticket, unit)
    }
    fn usage_observation_retire(
        &self,
        caller: &Caller,
        ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        unit: Option<u64>,
    ) {
        self.observation_retire(caller, ticket, unit);
    }
    fn usage_observation_input(
        &self,
        caller: &Caller,
        ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        unit: Option<u64>,
    ) -> Option<Vec<u8>> {
        self.observation_input(caller, ticket, unit)
    }
    fn usage_observation_submit(
        &self,
        caller: &Caller,
        ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        unit: Option<u64>,
        observation: busbar_contract::abi::sdk::plane::observation::Observation,
        done: busbar_contract::services::ObservationDone,
    ) -> Result<(), &'static str> {
        self.observation_submit(caller, ticket, unit, observation, done)
    }
    fn usage_observation_scope(
        &self,
        caller: &Caller,
        ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        unit: Option<u64>,
        request: busbar_contract::abi::sdk::plane::observation::ScopeRequest,
        done: busbar_contract::services::ObservationDone,
    ) -> Result<(), &'static str> {
        self.observation_scope_request(caller, ticket, unit, request, done)
    }

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
                    .by_reference(caller.namespace(), &reference)
                    .filter(|(_, work)| work.owner == owner)
                    .ok_or(InspectionError::NotFound)?;
                let retain_ms = self.work_bounds_of(caller.namespace()).retain_ms;
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
                let observations = sessions
                    .iter()
                    .map(|session| SessionObservation {
                        session: *session,
                        live: self.sessions.is_open(caller.incarnation(), *session),
                    })
                    .collect();
                Ok(InspectionObservation::CarrierSessions(observations))
            }
        }
    }

    fn now(&self) -> Reading {
        let wall = crate::store::now_ns();
        let mono_ns = self
            .mono_ns
            .as_ref()
            .map_or_else(|| since_origin_ns(self.origin), |mono| mono());
        Reading {
            wall_ns: wall,
            mono_ns,
        }
    }

    fn dest_judge(&self, dest: &str, class: u32, flags: u32, later: Option<Later>) -> Ran {
        let resolve = flags & svc::DEST_RESOLVE != 0;
        let refuse_private = flags & svc::DEST_REFUSE_PRIVATE != 0;
        let explain = flags & svc::DEST_EXPLAIN != 0;

        if class == busbar_contract::abi::host::conn::connector::EGRESS_OPERATOR_INFRASTRUCTURE {
            if !DEST_JUDGE_CLASS_FLAGGED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                crate::diagnostics::diag_warn!(
                    crate::diagnostics::PLUGIN_CALL_REFUSED_ABI_RULE,
                    "a plugin asked dest.judge under the operator-infrastructure egress class; \
                     refused (logged once per process)"
                );
                crate::audit::auditlog::record_plugin_refusal(
                    crate::audit::auditlog::PluginRefusal::Op,
                    "plugin",
                    "dest.judge",
                    "BUSBAR-6014",
                );
            }
            return Ran::Now(Stored::refused(DEST_JUDGE_OPERATOR_INFRASTRUCTURE));
        }
        let Some(j) = &self.judge else {
            return Ran::Now(Stored::refused(NO_DEST_JUDGE));
        };
        if flags & svc::DEST_PLAINTEXT_INTENT != 0 {
            return Ran::Now(Stored::ready(if j.plaintext_admitted(dest) {
                svc::DEST_ALLOWED
            } else {
                svc::DEST_PLAINTEXT
            }));
        }
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
        match self.native_records(caller, kind) {
            Err(refused) => return Ran::Now(refused),
            Ok(Some(records)) => {
                if Self::chain_of_facts(&records.facts, kind).is_some() {
                    return Ran::Now(Stored::refused(crate::host_chains::CHAIN_READ_WHOLE));
                }
                if let Some(value) = self.pending.get(caller.namespace(), kind, key) {
                    return Ran::Now(native_record_found(value));
                }
                let Some(pool) = self.pool() else {
                    return Ran::Now(Stored::refused(NO_POOL));
                };
                let schema = records.schema.as_str();
                let key = record_key(caller.namespace(), key);
                return submit_async(pool, later, async move {
                    match records.rows.get(schema, &key).await {
                        Ok(Some(value)) => {
                            native_record_found(value.expose(&crate::seal::lend()).clone())
                        }
                        Ok(None) => Stored::ready(svc::ABSENT),
                        Err(_) => failed(STORE_FAILED),
                    }
                });
            }
            Ok(None) => {}
        }
        Ran::Now(self.unbound(caller, kind))
    }

    fn records_list(&self, caller: &Caller, list: RecordsList, later: Later) -> Ran {
        match self.native_records(caller, &list.kind) {
            Err(refused) => return Ran::Now(refused),
            Ok(Some(records)) => {
                let Some(pool) = self.pool() else {
                    return Ran::Now(Stored::refused(NO_POOL));
                };
                let limit = if list.limit == 0 {
                    MAX_SPANS as usize
                } else {
                    (list.limit as usize).min(MAX_SPANS as usize)
                };
                let framing = Self::chain_of_facts(&records.facts, &list.kind);
                let queued = if framing.is_some() {
                    Vec::new()
                } else {
                    self.pending
                        .under(caller.namespace(), &list.kind, &list.prefix)
                };
                let Some(schema) = records
                    .facts
                    .record_kinds
                    .iter()
                    .find(|schema| schema.as_str() == list.kind)
                    .copied()
                else {
                    return Ran::Now(Stored::refused(NOT_ADMITTED));
                };
                let instance = Arc::clone(caller.namespace());
                let scope = crate::host_records::record_scope_len(&instance);
                let prefix = record_key(&instance, &list.prefix);
                return submit_async(pool, later, async move {
                    let mut rows = Vec::new();
                    let mut cursor = None;
                    loop {
                        let page = match records
                            .rows
                            .page(&list.kind, &prefix, cursor.as_ref())
                            .await
                        {
                            Ok(page) => page,
                            Err(_) => return failed(STORE_FAILED),
                        };
                        for (mut key, value) in page.rows {
                            if key.len() < scope {
                                return failed(STORE_FAILED);
                            }
                            key.drain(..scope);
                            rows.push((key, value.expose(&crate::seal::lend()).clone()));
                        }
                        cursor = page.next;
                        if cursor.is_none() {
                            break;
                        }
                    }
                    let rows = match framing {
                        Some(f) => crate::host_chains::verified(&instance, schema, rows, f),
                        None => rows,
                    };
                    spans_of(merge_list(rows, queued, list.after.as_deref(), limit))
                });
            }
            Ok(None) => {}
        }
        Ran::Now(self.unbound(caller, &list.kind))
    }

    fn records_claim(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        ttl_ms: u64,
        later: Later,
    ) -> Ran {
        if let Some(store) = self.persistence.as_ref() {
            let schema = match self.native_records(caller, kind) {
                Err(refused) => return Ran::Now(refused),
                Ok(scope) => scope.map(|scope| scope.schema),
            };
            if ttl_ms == 0 {
                return Ran::Now(Stored::refused(NO_TTL));
            }
            let Some(pool) = self.pool() else {
                return Ran::Now(failed(NO_POOL));
            };
            let Some(expires_ms) = (self.wall_ms)().checked_add(ttl_ms) else {
                return Ran::Now(Stored::refused(EXPIRY_OVERFLOW));
            };
            let expires_at = expires_ms.div_ceil(1000);
            if store
                .register_claim_scope(caller.namespace(), kind)
                .is_err()
            {
                return Ran::Now(failed(STORE_FAILED));
            }
            let token = claim_token(caller.namespace(), kind, key);
            let Some(schema) = schema else {
                return Ran::Now(failed(STORE_FAILED));
            };
            let claim_key = (Arc::clone(caller.namespace()), schema, token);
            let attempt = {
                let mut claims = self
                    .native_claims
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if !claims.contains_key(&claim_key)
                    && claims.len() >= crate::host_records::QUEUE_CAP
                {
                    return Ran::Now(failed(QUEUE_FULL));
                }
                let attempt = claims
                    .entry(claim_key.clone())
                    .or_insert(NativeClaimAttempt {
                        expires_at,
                        pending: None,
                        driving: false,
                    });
                if attempt.driving {
                    return Ran::Now(failed(POOL_REFUSED));
                }
                attempt.driving = true;
                *attempt
            };
            let guard = NativeClaimGuard {
                claims: Arc::clone(&self.native_claims),
                key: claim_key,
            };
            let store = Arc::clone(store);
            let instance = Arc::clone(caller.namespace());
            return submit_async(pool, later, async move {
                use crate::persistence::scoped::{ClaimOutcome, ScopedStore};
                let (_, kind, token) = &guard.key;
                let scoped = match ScopedStore::authorized(store, &instance, Vec::<String>::new()) {
                    Ok(scoped) => scoped,
                    Err(_) => return failed(STORE_FAILED),
                };
                let result = match attempt.pending {
                    Some(pending) => scoped.retry_claim(kind.as_str(), pending).await,
                    None => {
                        scoped
                            .redeem(kind.as_str(), token, attempt.expires_at)
                            .await
                    }
                };
                match result {
                    Ok(ClaimOutcome::Claimed) => {
                        guard
                            .claims
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .remove(&guard.key);
                        Stored::ready(svc::CLAIM_WON)
                    }
                    Ok(ClaimOutcome::AlreadyClaimed | ClaimOutcome::Expired) => {
                        guard
                            .claims
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .remove(&guard.key);
                        Stored::ready(svc::CLAIM_TAKEN)
                    }
                    Ok(
                        ClaimOutcome::Pending(pending)
                        | ClaimOutcome::Reconcile(pending)
                        | ClaimOutcome::Busy(pending),
                    ) => {
                        if let Some(attempt) = guard
                            .claims
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .get_mut(&guard.key)
                        {
                            attempt.pending = Some(pending);
                        }
                        failed(STORE_FAILED)
                    }
                    Err(_) => failed(STORE_FAILED),
                }
            });
        }
        // The caller's own standing and its `in` are judged first: a misconfigured claim is
        // REFUSED. Only a well-formed claim of a declared kind, on a host with no store bound,
        // is UNSERVED: the host keeps no claim ledger, and single use is the caller's own.
        if let Err(refused) = self.declared(caller, kind) {
            return Ran::Now(refused);
        }
        if ttl_ms == 0 {
            return Ran::Now(Stored::refused(NO_TTL));
        }
        if (self.wall_ms)().checked_add(ttl_ms).is_none() {
            return Ran::Now(Stored::refused(EXPIRY_OVERFLOW));
        }
        Ran::Now(Stored::unserved(NO_STORE))
    }

    fn sign(&self, caller: &Caller, data: &[u8]) -> Stored {
        let Some(facts) = self.facts(caller) else {
            return Stored::refused(NOT_ADMITTED);
        };
        let Some(signing) = facts.signing.as_ref() else {
            return Stored::refused(NO_DOMAIN);
        };
        // The key (prefix + kid) leads the answer, the signature follows. The prefix is written
        // first; the signer appends the signature and then its key id to the answer's own buffer;
        // the key id is rotated in front of the signature, in place.
        let mut stored = Stored::ready(0);
        let prefix_len = signing.kid_prefix.len();
        stored
            .bytes
            .extend_from_slice(signing.kid_prefix.as_bytes());
        let Some(sig_len) = self
            .signer
            .as_ref()
            .and_then(|s| s.sign(&signing.domain, data, &mut stored.bytes))
        else {
            return Stored::refused(NO_KEY);
        };
        let key_len = stored.bytes.len() - sig_len;
        stored.bytes[prefix_len..].rotate_right(key_len - prefix_len);
        stored.spans.push(span(0, key_len, key_len, sig_len));
        stored
    }

    fn trust_sight(&self, caller: &Caller, counterparty: &str, hash: &str, later: Later) -> Ran {
        // The sighting's one reading of the host clock: its judgement and its audit row's.
        let at_ms = (self.wall_ms)();
        let durable = match (self.demotions.as_ref(), self.pool()) {
            (Some(_), None) => return Ran::Now(Stored::refused(NO_POOL)),
            (Some(d), Some(pool)) => Some((d, pool)),
            (None, _) => None,
        };

        let permit = match self
            .trust
            .begin_sighting(caller.namespace(), counterparty, None)
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
        if !valid_trust_evidence(hash) {
            return Ran::Now(Stored::refused(INVALID_TRUST_EVIDENCE));
        }
        let (sight, effect) = match self
            .trust
            .sight(caller.namespace(), counterparty, hash, at_ms)
        {
            Ok(v) => v,
            Err(Unjudged::UnknownInstance) => return Ran::Now(Stored::refused(NOT_ADMITTED)),
            Err(Unjudged::UnknownCounterparty) => {
                return Ran::Now(Stored::refused(NOT_A_COUNTERPARTY));
            }
        };
        let answer = Stored::ready(sight_code(sight));
        let Some((d, pool)) = durable.filter(|_| effect != Effect::None) else {
            return Ran::Now(answer);
        };

        let record = Arc::clone(&d.record);
        let key = demotion_key(caller.namespace(), counterparty);
        // The settle job outlives this call, and the counterparty's name is the plugin's for the
        // call only: the job keeps one copy of it, for its audit row and (the default instance)
        // its unprefixed row. The instance's name is its caller's shared one.
        let (audit_instance, audit_counterparty) =
            (Arc::clone(caller.namespace()), counterparty.to_string());

        let unprefixed = d.default_instance.as_ref() == Some(caller.namespace());
        let owed = TrustSightOwed {
            permit: Some(permit),
            later: Some(later),
        };
        pool.run_async(Box::pin(async move {
            let settled = if effect == Effect::Demote {
                crate::trust::demotion::settle(&record, &key, crate::trust::TrustState::Quarantined)
                    .await
            } else {
                let result = crate::trust::demotion::settle(
                    &record,
                    &key,
                    crate::trust::TrustState::Approved,
                )
                .await;
                match (result, unprefixed) {
                    (Ok(()), true) => {
                        crate::trust::demotion::settle(
                            &record,
                            &audit_counterparty,
                            crate::trust::TrustState::Approved,
                        )
                        .await
                    }
                    (result, _) => result,
                }
            };
            // The kernel's own trust events are audited like an operator's (conditions B-N3,
            // B-C3): the quarantine, and the automatic clear that restores the counterparty.
            let action = if effect == Effect::Demote {
                "trust_quarantine"
            } else {
                "trust_unquarantine"
            };
            let at = (&*audit_instance, audit_counterparty.as_str(), None);
            if let Err(error) = settled {
                tracing::error!(%error,"the durable trust demotion could not be settled");
                kernel_trust_row(
                    action,
                    at,
                    crate::audit_ring::OUTCOME_DEGRADED,
                    "not_kept",
                    at_ms,
                );
                owed.answer(failed(DECISION_UNKEPT));
            } else {
                kernel_trust_row(action, at, crate::audit_ring::OUTCOME_APPLIED, "", at_ms);
                owed.answer(answer);
            }
        }));
        Ran::Later
    }

    fn records_secret(&self, kind: &str, id: &str, _later: Later) -> Ran {
        let Some(credentials) = self.credentials.as_ref() else {
            return Ran::Now(Stored::refused(NO_CREDENTIAL_SOURCE));
        };
        if !credentials.installed() {
            return Ran::Now(Stored::refused(NOT_READABLE));
        }
        let (secret, live) = credentials.read(kind, id);
        // A credential read answers in its own wiping buffer; the credential store keeps its copy.
        let bytes = busbar_contract::secure::SecureVec::from(
            secret.expose(&crate::seal::lend()).as_bytes(),
        );
        let span = ItemSpan {
            key: absent_span(),
            value: Span {
                offset: 0,
                len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            },
        };
        Ran::Now(Stored {
            bytes: bytes.into_vec(),
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
        let Some(principal) = self.sessions.emit(caller.incarnation(), session, bytes) else {
            return Stored::refused(SESSION_NOT_OPEN);
        };

        // `session:<u64>` is at most 28 bytes: the audit subject is spelled on the stack.
        let mut subject = [0u8; 28];
        let subject = {
            use std::io::Write as _;
            let mut at = &mut subject[..];
            let _ = write!(at, "session:{session}");
            let len = 28 - at.len();
            std::str::from_utf8(&subject[..len]).unwrap_or_default()
        };
        crate::audit::auditlog::emit_admin_hostless_now(
            SESSION_EMIT_ACTION,
            subject,
            busbar_contract::vocab::OUTCOME_APPLIED,
            &principal,
        );
        Stored::ready(0)
    }

    fn outbound_authorize(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        ask: busbar_contract::services::OutboundAuthorization<'_>,
        _later: Later,
    ) -> Ran {
        let refused = || Ran::Now(Stored::refused(crate::host_outbound::REFUSED));
        if caller.kind() != busbar_contract::abi::mechanism::KindCode::Plane {
            return refused();
        }
        let Some(unit) = unit else {
            return refused();
        };
        if !self.units.generic_effects_allowed(unit, caller) {
            return refused();
        }
        let Some(principal) = self.units.get(unit).and_then(|r| r.principal.clone()) else {
            return refused();
        };
        let now = (self.wall_ms)() / 1000;
        if !principal.enabled
            || principal.deleted_at.is_some()
            || principal.expires_at.is_some_and(|at| at <= now)
        {
            return refused();
        }
        if ask.action == svc::OUTBOUND_PREPARE {
            let Some(prepared) = crate::host_outbound::Prepared::new(&ask, now) else {
                return refused();
            };
            return if self.units.prepare_outbound(unit, prepared) {
                Ran::Now(Stored::ready(1))
            } else {
                refused()
            };
        }
        match self
            .outbound
            .authorize(caller, &principal.id, &ask, (self.wall_ms)() / 1000)
        {
            Ok((revision, bound)) => {
                if let Some(bound) = bound {
                    if !self.units.bind_outbound(unit, bound) {
                        return refused();
                    }
                }
                Ran::Now(Stored::ready(revision))
            }
            Err(_) => refused(),
        }
    }

    fn ticket_mint(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        ttl_secs: u64,
        record: &[u8],
        later: Later,
    ) -> Ran {
        let Some(unit) = unit else {
            return Ran::Now(Stored::refused(TICKET_NO_PRINCIPAL));
        };
        let Some(key) = self.units.get(unit).and_then(|r| r.principal.clone()) else {
            return Ran::Now(Stored::refused(TICKET_NO_PRINCIPAL));
        };
        let Some(facts) = self.facts(caller).filter(|f| f.ticket_prefix.is_some()) else {
            return Ran::Now(Stored::refused(TICKET_NO_PREFIX));
        };
        let Some(press) = self.tickets.as_ref().cloned() else {
            return Ran::Now(Stored::refused(TICKET_NO_PRESS));
        };
        let Some(pool) = self.pool() else {
            return Ran::Now(Stored::refused(NO_POOL));
        };
        let caller = caller.clone();
        let record = busbar_contract::Secret::new(record.to_vec());
        let now = (self.wall_ms)() / 1000;
        submit_async(pool, later, async move {
            let prefix = facts.ticket_prefix.as_deref().unwrap_or_default();
            match press
                .mint_for_unit(
                    unit,
                    &caller,
                    &key,
                    prefix,
                    ttl_secs,
                    record.expose(&crate::seal::lend()),
                    now,
                )
                .await
            {
                Ok((ticket, expires_at)) => Stored {
                    bytes: ticket.into_bytes(),
                    spans: Vec::new(),
                    ..Stored::ready(expires_at)
                },
                Err(refusal) => Stored {
                    value: svc::ticket_refused(refusal.code(), refusal.retry_after_secs()),
                    bytes: Vec::new(),
                    spans: Vec::new(),
                    ..Stored::refused(refusal.reason())
                },
            }
        })
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
        if busbar_contract::crypto::fill(&mut bytes).is_err() {
            return failed(NO_RANDOMNESS);
        }
        Stored {
            bytes,
            spans: Vec::new(),
            ..Stored::ready(0)
        }
    }

    fn trust_unreached(&self, caller: &Caller, counterparty: &str) -> Stored {
        match self.trust.last_verdict(caller.namespace(), counterparty) {
            Ok(sight) => Stored::ready(sight_code(sight)),
            Err(Unjudged::UnknownInstance) => Stored::refused(NOT_ADMITTED),
            Err(Unjudged::UnknownCounterparty) => Stored::refused(NOT_A_COUNTERPARTY),
        }
    }

    fn trust_decide(
        &self,
        caller: &Caller,
        ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        key: busbar_contract::services::TrustKeyRef<'_>,
        expected: Option<&str>,
        approve: bool,
        later: Later,
    ) -> Ran {
        if self.facts(caller).is_none() {
            return Ran::Now(Stored::refused(NOT_ADMITTED));
        }
        // The decision's one reading of the host clock: its stamp and its audit row's.
        let at_ms = (self.wall_ms)();
        let ruling = if approve {
            Ruling::Approve
        } else {
            Ruling::Revoke
        };
        // The grant carries the admin authority it was lent under (condition B-C1): no grant, a
        // grant for another counterparty, or one whose verbs do not admit this ruling decides
        // nothing.
        let granted = self
            .trust_decisions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(caller.incarnation().clone(), ticket))
            .filter(|granted| granted.name() == key.counterparty)
            .map(|granted| (granted.authority.clone(), granted.request_id.clone()));
        let Some((authority, request_id)) = granted.filter(|(a, _)| a.admits(ruling)) else {
            return Ran::Now(Stored::refused(NO_TRUST_DECISION_GRANT));
        };
        let key_text = trust_key(caller.namespace(), key.counterparty, key.item);
        let attempt = DecisionAttempt {
            instance: caller.namespace().to_string(),
            counterparty: key.counterparty.to_string(),
            item: key.item.map(str::to_string),
            ruling,
            reviewed: expected.map(|d| Some(d.to_string())),
            actor: DecidedBy::Instance {
                instance: caller.namespace().to_string(),
                principal: authority.principal,
            },
            operation: None,
            request_id,
            resource: format!("plane:{}", caller.namespace()),
        };
        // No key-only approve through the plugin interface either (r3 §4.2c). A revoke without a
        // reviewed digest stays unconditional: it can never trust anything.
        let reviewed = match (ruling, expected) {
            (Ruling::Approve, None) => {
                let decided = audit_decision(&attempt, &key_text, Err(TrustRefused::Stale), at_ms);
                return Ran::Now(trust_decision_answer(decided.result));
            }
            (_, Some(digest)) => Some(Reviewed::Seen(digest)),
            (Ruling::Revoke, None) => None,
        };
        let Some(record) = self.trust_decision_record() else {
            let decided =
                audit_decision(&attempt, &key_text, Err(TrustRefused::Unavailable), at_ms);
            return Ran::Now(trust_decision_answer(decided.result));
        };
        let work = match self.prepare_decision(&attempt, reviewed, record, at_ms) {
            Ok(work) => work,
            Err(why) => {
                let decided = audit_decision(&attempt, &key_text, Err(why), at_ms);
                return Ran::Now(trust_decision_answer(decided.result));
            }
        };
        let Some(pool) = self.pool() else {
            return Ran::Now(Stored::refused(NO_POOL));
        };
        submit_async(pool, later, async move {
            let result = work.finish().await;
            trust_decision_answer(audit_decision(&attempt, &key_text, result, at_ms).result)
        })
    }

    fn trust_state(&self, caller: &Caller, counterparty: &str) -> Stored {
        let all = self.trust.rows();
        let rows = || {
            all.iter().filter(|r| {
                r.instance.as_str() == caller.namespace().as_ref() && r.counterparty == counterparty
            })
        };
        let Some(whole) = rows().find(|r| r.item.is_none()) else {
            return Stored::refused(if self.facts(caller).is_some() {
                NOT_A_COUNTERPARTY
            } else {
                NOT_ADMITTED
            });
        };
        let mut stored = Stored::ready(key_code(whole.state));
        let cap = usize::try_from(MAX_SPANS).unwrap_or(usize::MAX);
        for row in rows().filter(|r| r.item.is_some()).take(cap) {
            let item = row.item.as_deref().unwrap_or_default();
            let off = stored.bytes.len();
            stored.bytes.extend_from_slice(item.as_bytes());
            // The value: `state\0approved\0seen`, written straight into the answer.
            let value_off = stored.bytes.len();
            stored.bytes.extend_from_slice(row.state.word().as_bytes());
            stored.bytes.push(0);
            stored
                .bytes
                .extend_from_slice(row.approved.as_deref().unwrap_or_default().as_bytes());
            stored.bytes.push(0);
            stored
                .bytes
                .extend_from_slice(row.seen.as_deref().unwrap_or_default().as_bytes());
            let value_len = stored.bytes.len() - value_off;
            stored
                .spans
                .push(span(off, item.len(), value_off, value_len));
        }
        stored
    }

    fn trust_sight_item(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: &str,
        digest: &str,
        later: Later,
    ) -> Ran {
        let mut permit =
            match self
                .trust
                .begin_sighting(caller.namespace(), counterparty, Some(item))
            {
                Ok(permit) => permit,
                Err(Undecided::NoSuchKey) => {
                    return Ran::Now(Stored::refused(if self.facts(caller).is_some() {
                        NOT_A_COUNTERPARTY
                    } else {
                        NOT_ADMITTED
                    }))
                }
                Err(_) => return Ran::Now(Stored::refused(DECISION_UNKEPT)),
            };
        if !valid_trust_evidence(digest) {
            return Ran::Now(Stored::refused(INVALID_TRUST_EVIDENCE));
        }
        match self
            .trust
            .sight_item_kept(caller.namespace(), counterparty, item, digest)
        {
            Ok((sight, demotion)) => {
                if demotion.is_some() {
                    permit.demoted();
                }
                let Some((fact, record)) =
                    demotion.zip(self.demotions.as_ref().map(|d| Arc::clone(&d.record)))
                else {
                    return Ran::Now(Stored::ready(sight_code(sight)));
                };
                let Some(pool) = self.pool() else {
                    return Ran::Now(Stored::refused(NO_POOL));
                };
                let at_ms = (self.wall_ms)();
                let now = at_ms / 1000;
                submit_async(pool, later, async move {
                    let _permit = permit;
                    let at = (
                        fact.instance.as_str(),
                        fact.counterparty.as_str(),
                        fact.item.as_deref(),
                    );
                    match record.keep_decision(&fact, now).await {
                        Ok(()) => {
                            kernel_trust_row(
                                "trust_demote",
                                at,
                                crate::audit_ring::OUTCOME_APPLIED,
                                "",
                                at_ms,
                            );
                            Stored::ready(sight_code(sight))
                        }
                        Err(error) => {
                            tracing::error!(%error,"an item's drift demotion could not be kept; it holds in this process");
                            kernel_trust_row(
                                "trust_demote",
                                at,
                                crate::audit_ring::OUTCOME_DEGRADED,
                                "not_kept",
                                at_ms,
                            );
                            failed(DECISION_UNKEPT)
                        }
                    }
                })
            }
            Err(Unjudged::UnknownInstance) => Ran::Now(Stored::refused(NOT_ADMITTED)),
            Err(Unjudged::UnknownCounterparty) => Ran::Now(Stored::refused(NOT_A_COUNTERPARTY)),
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
        Stored::ready(match self.trust.judge(caller.namespace(), &facts) {
            Ok(()) => svc::DISTRUST_NONE,
            Err(why) => distrust_code(why),
        })
    }

    fn trust_due(&self, caller: &Caller) -> Stored {
        let Some(names) = self.trust.due(caller.namespace()) else {
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
        let key = match self.trust.root_key(caller.namespace(), cp) {
            Ok(Some(key)) => key,
            Ok(None) => return Stored::refused(NO_ROOT_KEY),
            Err(Unjudged::UnknownInstance) => return Stored::refused(NOT_ADMITTED),
            Err(Unjudged::UnknownCounterparty) => return Stored::refused(NOT_A_COUNTERPARTY),
        };
        let sigs = match sigs {
            [] => busbar_contract::json::Value::new(),
            json => match busbar_contract::json::parse_value(json) {
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

    fn unit_nest(&self, _caller: &Caller, _unit: Option<u64>, _ask: NestAsk, _later: Later) -> Ran {
        // The legacy crossing has no invocation authority. MIN-3 dispatch uses
        // InvocationContext; numeric request IDs cannot recover that authority.
        Ran::Now(Stored::refused(NEST_NO_UNIT))
    }

    fn work_open(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        kind: &str,
        record: &[u8],
        later: Later,
    ) -> Ran {
        let recovery = match self.capture_recovery(caller, unit, record) {
            Ok(binding) => binding,
            Err(why) => return Ran::Now(Stored::refused(why)),
        };
        match self.native_work_writer(caller) {
            Err(refused) => return Ran::Now(refused),
            Ok(Some(writer)) => {
                let Some(facts) = self.facts(caller) else {
                    return Ran::Now(Stored::refused(NOT_ADMITTED));
                };
                if !facts
                    .record_kinds
                    .iter()
                    .any(|schema| schema.as_str() == kind)
                {
                    return Ran::Now(Stored::refused(NOT_A_KIND));
                }
                if record.len() > svc::MAX_WORK_RECORD {
                    return Ran::Now(Stored::refused(work_refusal::TOO_LONG));
                }
                let Some(owner) = self.owner_of_unit(unit) else {
                    return Ran::Now(Stored::refused(work_refusal::NO_UNIT));
                };
                let book = Arc::clone(&self.work);
                let bounds = self.work_bounds_of(caller.namespace());
                let wall_ms = Arc::clone(&self.wall_ms);
                let kind = busbar_contract::kept::Text::from(Arc::<str>::from(kind));
                let record = record.to_vec();
                let owed = Owed(Some(later));
                let pool = Arc::clone(&writer.pool);
                pool.run_async(Box::pin(async move {
                    let rows = match writer.rows() {
                        Ok(rows) => rows,
                        Err(_) => {
                            owed.answer(failed(STORE_FAILED));
                            return;
                        }
                    };
                    if book.load_native(&rows, &writer.instance).await.is_err() {
                        owed.answer(failed(STORE_FAILED));
                        return;
                    }
                    let now_ms = wall_ms();
                    for gone in book.sweep(&writer.instance, now_ms, bounds.retain_ms) {
                        if let Ok(empty) = RecordBytes::new(Vec::new()) {
                            let gone = gone.to_vec();
                            writer.put(gone, empty, Box::new(|_| {}));
                        }
                    }
                    let mut reference = [0; 16];
                    if busbar_contract::crypto::fill(&mut reference).is_err() {
                        owed.answer(failed(NO_RANDOMNESS));
                        return;
                    }
                    let work = Work {
                        instance: Arc::clone(&writer.instance),
                        reference,
                        kind,
                        owner,
                        live: true,
                        opened_ms: now_ms,
                        settled_ms: 0,
                        record,
                        bound: None,
                        opened_by: unit,
                        recovery,
                    };
                    let Some(row) = work.row() else {
                        owed.answer(Stored::refused(work_refusal::TOO_LONG));
                        return;
                    };
                    let Some(handle) = book.reserve(work, bounds.max_live) else {
                        owed.answer(Stored::refused(work_refusal::AT_BOUND));
                        return;
                    };
                    let opening = WorkOpening {
                        book,
                        handle,
                        reference,
                        owed: Some(owed),
                    };
                    let key = reference.to_vec();
                    writer.put(key, row, Box::new(move |result| opening.answer(result)));
                }));
                return Ran::Later;
            }
            Ok(None) => {}
        }
        Ran::Now(self.work_unbound(caller))
    }

    fn work_find(&self, caller: &Caller, unit: Option<u64>, reference: &[u8], later: Later) -> Ran {
        match self.native_work_writer(caller) {
            Err(refused) => return Ran::Now(refused),
            Ok(Some(writer)) => {
                let (Some(unit), Some(owner)) = (unit, self.owner_of_unit(unit)) else {
                    return Ran::Now(Stored::refused(work_refusal::NO_UNIT));
                };
                let Some(reference) = parse_reference(reference) else {
                    return Ran::Now(Stored::ready(svc::ABSENT));
                };
                let book = Arc::clone(&self.work);
                let units = Arc::clone(&self.units);
                let retain_ms = self.work_bounds_of(caller.namespace()).retain_ms;
                let wall_ms = Arc::clone(&self.wall_ms);
                let pool = Arc::clone(&writer.pool);
                return submit_async(&*pool, later, async move {
                    let held = match book.by_reference(&writer.instance, &reference) {
                        Some(held) => Some(held),
                        None => {
                            let rows = match writer.rows() {
                                Ok(rows) => rows,
                                Err(_) => return failed(STORE_FAILED),
                            };
                            match rows.get(WORK_SCHEMA.as_str(), &reference).await {
                                Err(_) => return failed(STORE_FAILED),
                                Ok(row) => row
                                    .and_then(|row| {
                                        Work::read(
                                            &writer.instance,
                                            reference,
                                            row.expose(&crate::seal::lend()),
                                        )
                                    })
                                    .map(|work| (book.adopt(work.clone()), work)),
                            }
                        }
                    };
                    match held {
                        Some((handle, work))
                            if work.owner == owner
                                && (work.live
                                    || work.settled_ms.saturating_add(retain_ms) > wall_ms()) =>
                        {
                            book.found(handle, unit, &|unit| units.get(unit).is_some());
                            work_found(handle, &work)
                        }
                        _ => Stored::ready(svc::ABSENT),
                    }
                });
            }
            Ok(None) => {}
        }
        Ran::Now(self.work_unbound(caller))
    }

    fn work_status(&self, caller: &Caller, reference: &[u8], later: Later) -> Ran {
        match self.native_work_writer(caller) {
            Err(refused) => return Ran::Now(refused),
            Ok(Some(writer)) => {
                let Some(reference) = parse_reference(reference) else {
                    return Ran::Now(Stored::ready(svc::WORK_STATUS_ABSENT));
                };
                let book = Arc::clone(&self.work);
                let retain_ms = self.work_bounds_of(caller.namespace()).retain_ms;
                let wall_ms = Arc::clone(&self.wall_ms);
                let pool = Arc::clone(&writer.pool);
                return submit_async(&*pool, later, async move {
                    let rows = match writer.rows() {
                        Ok(rows) => rows,
                        Err(_) => return failed(STORE_FAILED),
                    };
                    match book
                        .status_native(&rows, &writer.instance, &reference, wall_ms(), retain_ms)
                        .await
                    {
                        Ok(status) => Stored::ready(status),
                        Err(_) => failed(STORE_FAILED),
                    }
                });
            }
            Ok(None) => {}
        }
        Ran::Now(self.work_unbound(caller))
    }

    fn work_settle(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        handle: u64,
        record: &[u8],
        later: Later,
    ) -> Ran {
        match self.native_work_writer(caller) {
            Err(refused) => return Ran::Now(refused),
            Ok(Some(writer)) => {
                if record.len() > svc::MAX_WORK_RECORD {
                    return Ran::Now(Stored::refused(work_refusal::TOO_LONG));
                }
                let owner = self.owner_of_unit(unit);
                let in_flight = |unit| self.units.get(unit).is_some();
                let record = record.to_vec();
                let settled = match self.work.settle(
                    caller.namespace(),
                    handle,
                    owner.as_ref(),
                    &in_flight,
                    record,
                    (self.wall_ms)(),
                ) {
                    Ok(settled) => settled,
                    Err(why) => return Ran::Now(Stored::refused(why)),
                };
                let Some(row) = settled.row() else {
                    self.work.cancel_settle(handle);
                    return Ran::Now(Stored::refused(work_refusal::TOO_LONG));
                };
                let key = settled.reference.to_vec();
                let unwritten = Unwritten {
                    book: Arc::clone(&self.work),
                    handle,
                    settled: Some(settled),
                    later: Some(later),
                };
                writer.put(
                    key,
                    row,
                    Box::new(move |result| match result {
                        Err(crate::host_records::WRITE_DROPPED) => drop(unwritten),
                        result => unwritten.answer(result.is_ok()),
                    }),
                );
                return Ran::Later;
            }
            Ok(None) => {}
        }
        Ran::Now(self.work_unbound(caller))
    }

    fn work_resume(&self, caller: &Caller, unit: Option<u64>, handle: u64, _later: Later) -> Ran {
        if self.facts(caller).is_none() {
            return Ran::Now(Stored::refused(NOT_ADMITTED));
        }
        let (Some(unit), Some(owner)) = (unit, self.owner_of_unit(unit)) else {
            return Ran::Now(Stored::refused(work_refusal::NO_UNIT));
        };
        Ran::Now(
            match self.work.bind(caller.namespace(), handle, &owner, unit) {
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
            .lookup(caller.namespace(), key, (self.wall_ms)(), later)
    }

    fn verify_store(&self, caller: &Caller, key: &[u8], entry: &[u8], ttl_ms: u64) -> Stored {
        if self.facts(caller).is_none() {
            return Stored::refused(NOT_ADMITTED);
        }
        self.verify
            .store(caller.namespace(), key, entry, ttl_ms, (self.wall_ms)())
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
        let content = content.to_vec();
        stage.scan(
            content,
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

    fn snapshot_read(&self, _caller: &Caller, scope: u32, later: Later) -> Ran {
        // Capture the crossing's owned authorization before moving onto an async task.
        let read = crate::export::scrape::read(scope);
        let Some(pool) = self.pool() else {
            return Ran::Now(Stored::refused(NO_POOL));
        };
        submit_async(pool, later, async move { read.await.stored() })
    }
}

pub(crate) const STAGE_NO_UNIT: &str = "the crossing serves no unit in flight";

pub(crate) const STAGE_NOT_BOUND: &str = "the unit's hook stage is not bound yet";

pub(crate) const STAGE_NOT_YOURS: &str = "the unit runs on another instance";

pub(crate) const STAGE_ANSWERED_AMISS: &str = "the hook stage answered outside the service's shape";

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
        if stage.instance() != caller.namespace().as_ref() {
            return Err(Stored::refused(STAGE_NOT_YOURS));
        }
        Ok(stage)
    }
}

pub type Judged = Box<dyn FnOnce(Result<SocketAddr, u64>) + Send>;

pub type Admitted = Result<(SocketAddr, Vec<IpAddr>), Refused>;

fn judged(v: Admitted, explain: bool) -> Stored {
    use std::io::Write as _;
    // Each key (an admitted address, or the refusal's detail) is written straight into the answer.
    fn key_span(s: &mut Stored, at: usize) {
        s.spans.push(ItemSpan {
            value: absent_span(),
            ..span(at, s.bytes.len() - at, 0, 0)
        });
    }
    match v {
        Ok((_, addrs)) => {
            let mut s = Stored::ready(svc::DEST_ALLOWED);
            for addr in &addrs {
                let at = s.bytes.len();
                let _ = write!(s.bytes, "{addr}");
                key_span(&mut s, at);
            }
            s
        }
        Err(r) => {
            let mut s = Stored::ready(r.verdict);
            if let Some(detail) = r.detail.filter(|_| explain) {
                s.bytes.extend_from_slice(detail.as_bytes());
                key_span(&mut s, 0);
            }
            s
        }
    }
}

impl KernelServices {
    /// A connector destination, with explicit security intent supplied by its transport.
    pub fn judge_destination(
        &self,
        target: Destination<'_>,
        done: Judged,
    ) -> Option<Result<SocketAddr, u64>> {
        let pin = |v: Admitted| v.map(|(addr, _)| addr).map_err(|r| r.verdict);
        match &self.judge {
            Some(j) => j
                .judge_target(target, false, false, Box::new(move |v| done(pin(v))))
                .map(pin),
            None => Some(Err(svc::DEST_NO_HOST)),
        }
    }

    /// Legacy host call: a bare authority has unknown security and is conservatively plaintext.
    pub fn judge_dial(
        &self,
        dest: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, u64>> {
        if !dest.contains("://") {
            return self.judge_destination(
                Destination {
                    authority: dest,
                    secure: false,
                    egress_class: class,
                },
                done,
            );
        }
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
#[path = "tests/trust_admin_custody_tests.rs"]
mod trust_admin_custody_tests;

#[cfg(test)]
#[path = "tests/trust_resolution_tests.rs"]
mod trust_resolution_tests;

#[cfg(test)]
#[path = "tests/host_nest_tests.rs"]
mod host_nest_tests;

#[must_use]
pub(crate) fn decided_code(state: KeyState) -> u64 {
    match state {
        KeyState::Same | KeyState::Approved => svc::TRUST_DECIDED_SERVING,
        KeyState::New => svc::TRUST_DECIDED_PENDING,
        KeyState::Drifted | KeyState::Quarantined => svc::TRUST_DECIDED_QUARANTINED,
    }
}

#[must_use]
pub(crate) fn key_code(state: KeyState) -> u64 {
    match state {
        KeyState::New => svc::KEY_NEW,
        KeyState::Same => svc::KEY_SAME,
        KeyState::Drifted => svc::KEY_DRIFTED,
        KeyState::Quarantined => svc::KEY_QUARANTINED,
        KeyState::Approved => svc::KEY_APPROVED,
    }
}

#[must_use]
pub(crate) fn sight_code(sight: Sight) -> u64 {
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

/// Core-owned authority issuer for the loader's validated bindings. The root wires
/// this provider; plugins cannot depend on the kernel or receive this value.
pub fn caller_binding() -> Arc<dyn busbar_contract::services::CallerBinding> {
    struct Binding;
    impl busbar_contract::services::CallerBinding for Binding {
        fn bind(
            &self,
            namespace: Arc<str>,
            kind: busbar_contract::abi::mechanism::KindCode,
        ) -> Caller {
            Caller::issue(&crate::seal::acquire(), namespace, kind)
        }
    }
    Arc::new(Binding)
}

#[cfg(any(test, feature = "test-support"))]
impl TrustDecisionAuthority {
    /// An authority admitting both rulings, as the admin gate builds one for a full grant.
    #[must_use]
    pub fn for_test() -> Self {
        Self {
            principal: "op".to_string(),
            approve: true,
            revoke: true,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl KernelServices {
    /// An operator who reviews the key's current state and then decides: the admin decision with
    /// the key's present `seen` as the review (TRUST-ADMIN-PRODUCER-DESIGN r3 §10.1 (R)).
    pub async fn trust_rule_reviewed(
        &self,
        key: &str,
        ruling: Ruling,
    ) -> Result<KeyRow, TrustRefused> {
        let seen = self
            .trust_rows()
            .into_iter()
            .find(|row| row.key() == key)
            .and_then(|row| row.seen);
        let reviewed = seen.as_deref().map_or(Reviewed::Unsighted, Reviewed::Seen);
        self.trust_rule_by(key, ruling, reviewed, "op", None)
            .await
            .result
    }

    /// This kernel with trust custody: a decision record bound to an in-memory test Store
    /// (TRUST-ADMIN-PRODUCER-DESIGN r3 §6, condition A-C1).
    #[must_use]
    pub async fn with_test_custody(self) -> Self {
        let record = Arc::new(DemotionRecord::new());
        record
            .set_store(Arc::new(
                crate::persistence::test_backend::attach(Arc::new(
                    crate::persistence::test_backend::Backend::default(),
                ))
                .await,
            ))
            .expect("a fresh record attaches");
        self.with_demotions(record, "")
    }
}
