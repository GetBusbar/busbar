// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use crate::open_once::OpenOnce;
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{Blob, DeadlineClass, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::slot as life;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::secret::{
    slot, CheckIn, ResolveIn, ResolveOut, ERROR_KIND_DENIED, ERROR_KIND_INTERNAL,
    ERROR_KIND_UNAVAILABLE, ERROR_KIND_UNSET, FIRST_SECRET_CAP, MAX_SECRET_BYTES,
};
use busbar_contract::config_time::{ConfigScope, RESOLVE_OFF_CONFIG_TIME};
use busbar_contract::conn::admissions::AdmissionAuthority;
use busbar_contract::redacted::Secret as SecretValue;
use busbar_contract::secret::{
    RelendCause, RelendRefused, SecretAxis, SecretCalls, SecretRefused, SecretRelent,
};
use busbar_contract::secret_ref::SecretRef;
use busbar_contract::secure::SecureVec;

use crate::boot::Candidate;
use crate::cold::secret_calls::{
    answer_text, check_answered, check_failed, declares_unread, encode_refused, instance_label,
    label, lane_copies, lent_material, load_refused, module_name, not_a_secret_door,
    open_timed_out, open_unsealed, open_without_ticket, refused_fmt, secret_blobs,
    statement_unread, unanswered, unencodable_settings, unsealed_check,
};
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::lifecycle::{self, blob, AnswerLease};
use crate::dispatch::Called;
use crate::dispatch::{
    in_head, instant_at, now_ns, out_head, Bind, ConnTable, Dispatcher, EnvelopeSink, Frame,
    NoSink, Plugin, PluginLogConfig, NO_BLOB,
};

const CALL_DEADLINE: Duration = Duration::from_secs(30);

const WAIT: Duration = Duration::from_secs(40);

const MAX_INFLIGHT_CAP: u32 = 16;

pub type DiskRun = fn(Box<dyn FnOnce() + Send>) -> Result<(), String>;

type DiskJob = Box<dyn FnOnce() + Send>;

struct QueuedDiskResolve {
    pending: Arc<Mutex<Option<DiskJob>>>,
    deadline: Instant,
}

impl QueuedDiskResolve {
    fn take(&self) -> Option<DiskJob> {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        pending.take()
    }

    fn run(self) {
        let Some(job) = self.take() else {
            return;
        };
        if instant_at(now_ns()) < self.deadline {
            job();
        }
    }
}

impl Drop for QueuedDiskResolve {
    fn drop(&mut self) {
        drop(self.take());
    }
}

/// Where a secret instance's `resolve` runs.
#[derive(Debug, Clone, Copy)]
enum Disk {
    /// On the dispatcher, from any caller: a source that does not read the disk.
    No,
    /// On the host's disk lane, at config time only: a source that declares a disk need.
    Lane(DiskRun),
    /// A source that declares a disk need, on a host that wired no lane: every resolve refused.
    Unwired,
}

pub struct LoadedSecret {
    opened: Arc<Opened>,
    dispatcher: Arc<Dispatcher>,
    next_worker: AtomicU32,
    disk: Disk,
    relending: Option<Relending>,
}

struct Opened {
    plugin: Arc<Plugin<Secret>>,
    /// The instance's tick driver (`dispatch::ticks`), stopped before the instance closes.
    schedule: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// What a re-lend needs to re-resolve an instance's own references and, for a plugin with no
/// `refresh`, open its successor: the BUILD'S OWN candidate (never the global dropped set, which a
/// later admission replaces), the settings as written and the references the Statement lends.
struct RelendSpec {
    module: String,
    label: String,
    settings: busbar_contract::plugin_settings::Settings,
    keys: Vec<String>,
    sugars: busbar_contract::secret_ref::Sugars,
    candidate: Candidate,
    loader: Loader,
}

/// One instance's re-lend state: its spec, the fingerprint of what it was lent (never the
/// material; no `Debug`) and the generation its next `refresh` opens.
struct Relending {
    spec: Arc<RelendSpec>,
    fingerprint: Mutex<[u8; 32]>,
    generation: std::sync::atomic::AtomicU64,
}

/// How the rows load and place one candidate's instance: copyable function pointers, so a re-lend
/// can open a successor long after the rows that opened the first one moved on.
#[derive(Clone, Copy)]
struct Loader {
    dispatcher: fn() -> Arc<Dispatcher>,
    conns: fn() -> Option<AdmissionAuthority>,
    logs: Option<fn() -> PluginLogConfig>,
    disk_run: Option<DiskRun>,
}

impl Loader {
    fn load(&self, c: &Candidate, label: &str) -> Result<Plugin<Secret>, String> {
        let sink: Arc<dyn EnvelopeSink> = match self.logs {
            Some(logs) => Arc::new(
                logs()
                    .sink(label, KindCode::Secret, Arc::new(NoSink))
                    .map_err(|e| load_refused(&c.name, &e))?,
            ),
            None => Arc::new(NoSink),
        };
        let bind = Bind {
            instance: instance_label(label),
            max_inflight_cap: MAX_INFLIGHT_CAP,
            sink,
            dispatcher: (self.dispatcher)().adopter(),

            conns: ConnTable::serving((self.conns)()),
        };
        crate::boot::open_candidate::<Secret>(c, bind).map_err(|e| load_refused(&c.name, &e))
    }

    fn placed(&self, c: &Candidate, opened: LoadedSecret) -> LoadedSecret {
        if c.disk {
            opened.reading_disk(self.disk_run)
        } else {
            opened
        }
    }
}

fn lent_fingerprint<S: busbar_contract::plugin::KernelSeal + ?Sized>(
    secrets: &[SecretValue<Vec<u8>>],
    seal: &S,
) -> [u8; 32] {
    busbar_contract::redacted::fingerprint(secrets.iter().map(|s| s.expose(seal).as_slice()))
}

impl RelendSpec {
    /// Open an instance of the build's own candidate over `settings` and the lent `secrets`, ready
    /// to re-lend.
    fn open(
        self: &Arc<Self>,
        settings: &[u8],
        secrets: &[SecretValue<Vec<u8>>],
    ) -> Result<LoadedSecret, String> {
        let dispatcher = (self.loader.dispatcher)();
        let fingerprint = {
            let seal = dispatcher
                .seal()
                .ok_or("secret module opening requires the host settings seal")?;
            lent_fingerprint(secrets, seal)
        };
        let opened = LoadedSecret::open(
            self.loader.load(&self.candidate, &self.label)?,
            Arc::clone(&dispatcher),
            settings,
            secrets,
        )?;
        let mut opened = self.loader.placed(&self.candidate, opened);
        opened.relending = Some(Relending {
            spec: Arc::clone(self),
            fingerprint: Mutex::new(fingerprint),
            generation: std::sync::atomic::AtomicU64::new(1),
        });
        Ok(opened)
    }
}

impl std::fmt::Debug for LoadedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedSecret")
            .field("plugin", &self.opened.plugin.name())
            .field("disk", &self.disk)
            .finish_non_exhaustive()
    }
}

struct Lending {
    settings: SecureVec,
    held: Mutex<SecretValue<Vec<u8>>>,
}

impl Lending {
    fn new(settings: &[u8], cap: usize) -> (Arc<Self>, ResolveIn) {
        let mut held = SecretValue::zeroed(cap);
        let (buf, cap) = held.lend_mut();
        let settings = SecureVec::from(settings);
        let lending = Arc::new(Self {
            settings,
            held: Mutex::new(held),
        });
        let input = resolve_in(blob(&lending.settings, BLOB_JSON, 0), buf, cap);
        (lending, input)
    }

    fn take(&self, len: usize) -> SecretValue<Vec<u8>> {
        let mut held =
            std::mem::take(&mut *self.held.lock().unwrap_or_else(PoisonError::into_inner));
        held.keep(len);
        held
    }
}

fn resolve_in(settings: Blob, secret_buf: *mut u8, secret_cap: usize) -> ResolveIn {
    ResolveIn {
        head: in_head(),
        settings,
        secret_buf,
        secret_cap,
    }
}

fn resolve_out() -> ResolveOut {
    ResolveOut {
        head: out_head(),
        secret: NO_BLOB,
        error_kind: ERROR_KIND_UNSET,
        _reserved: 0,
        needed: 0,
    }
}

fn regrown(out: &ResolveOut) -> usize {
    usize::try_from(out.needed)
        .unwrap_or(FIRST_SECRET_CAP)
        .min(MAX_SECRET_BYTES)
}

const CHECK_REASON_CAP: usize = 4096;

pub fn check(plugin: &Plugin<Secret>, settings: &[u8]) -> Result<(), Vec<String>> {
    let mut reason = vec![0_u8; CHECK_REASON_CAP];
    let mut f = Frame::new(
        CheckIn {
            head: in_head(),
            settings: blob(settings, BLOB_JSON, 0),
            err_buf: reason.as_mut_ptr(),
            err_cap: reason.len(),
        },
        out_head(),
    );
    let c = plugin.call(slot::CHECK, &mut f);
    let _lease = AnswerLease::new(plugin, c.lease);
    let name = plugin.name();
    match c.outcome {
        Outcome::Ready | Outcome::Refused => Ok(()),
        Outcome::Failed => Err(check_failed(name, c.error.as_deref().unwrap_or_default())),
        o => Err(check_answered(name, o)),
    }
}

fn refused(error_kind: u32, text: String) -> SecretRefused {
    SecretRefused { error_kind, text }
}

fn changed_size(name: &str) -> SecretRefused {
    refused_fmt(
        ERROR_KIND_UNAVAILABLE,
        format_args!(
            "secret module '{name}' could not resolve: the secret's value changed size between \
             the host's two reads; resolve it again"
        ),
    )
}

fn short_again(outcome: Outcome, out: &ResolveOut, lent: usize) -> bool {
    outcome == Outcome::Fault && out.needed > lent as u64
}

impl LoadedSecret {
    /// OPEN an instance through the dispatcher, as every other op on it crosses: a PENDING open
    /// (a plugin that authenticates before it is ready) is resumed by the dispatcher until it
    /// answers READY or the wait ends.
    pub fn open(
        plugin: Plugin<Secret>,
        dispatcher: Arc<Dispatcher>,
        settings: &[u8],
        secrets: &[SecretValue<Vec<u8>>],
    ) -> Result<Self, String> {
        let owned: Vec<SecureVec> = match (secrets.is_empty(), dispatcher.seal()) {
            (true, _) => Vec::new(),
            (false, Some(seal)) => lent_material(secrets, seal),
            (false, None) => return Err(open_unsealed(plugin.name())),
        };
        let lent = Arc::new(lifecycle::OpenLent::new(settings, owned));
        let f = lent.frame();
        let Some(ticket) = dispatcher.mint(0) else {
            return Err(open_without_ticket(plugin.name()));
        };
        let deadline = now_ns().saturating_add(CALL_DEADLINE.as_nanos() as u64);
        let done = dispatcher
            .submit_lent(
                &plugin,
                ticket,
                life::OPEN,
                f,
                DeadlineClass::Call,
                deadline,
                lent as crate::dispatch::Lent,
            )
            .wait(WAIT);
        dispatcher.recycle(ticket);
        let Some(done) = done else {
            return Err(open_timed_out(plugin.name(), WAIT.as_secs()));
        };
        let opened = AnswerLease::new(&plugin, done.lease);
        if done.outcome != Outcome::Ready || done.detached || done.disposition.is_some() {
            let called = Called {
                outcome: done.outcome,
                error: done.error,
                lease: 0,
                recall: None,
            };
            return Err(called.open_failure(plugin.name()));
        }
        drop(opened);
        let plugin = Arc::new(plugin);
        let schedule = crate::dispatch::ticks::spawn(
            Arc::clone(&plugin),
            Arc::clone(&dispatcher),
            0,
            Arc::default(),
        );
        Ok(Self {
            opened: Arc::new(Opened {
                plugin,
                schedule: Mutex::new(schedule),
            }),
            dispatcher,
            next_worker: AtomicU32::new(0),
            disk: Disk::No,
            relending: None,
        })
    }

    #[must_use]
    pub fn reading_disk(mut self, lane: Option<DiskRun>) -> Self {
        self.disk = lane.map_or(Disk::Unwired, Disk::Lane);
        self
    }

    pub fn name(&self) -> &str {
        self.opened.plugin.name()
    }

    fn resolve_on_lane(
        &self,
        lane: DiskRun,
        settings: &[u8],
    ) -> Result<SecretValue<Vec<u8>>, SecretRefused> {
        let (name, owned) = lane_copies(self.name(), settings);
        let deadline = instant_at(now_ns()) + WAIT;
        let opened = Arc::clone(&self.opened);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let work: DiskJob = Box::new(move || {
            let _ = tx.send(opened.resolve_here(&owned));
        });
        let pending = Arc::new(Mutex::new(Some(work)));
        let waiting = QueuedDiskResolve {
            pending: Arc::clone(&pending),
            deadline,
        };
        let queued = QueuedDiskResolve { pending, deadline };
        lane(Box::new(move || queued.run())).map_err(|e| {
            refused_fmt(
                ERROR_KIND_UNAVAILABLE,
                format_args!("secret module '{name}' could not reach the host's disk lane: {e}"),
            )
        })?;
        // The budget was read once, into `deadline`; only a non-blocking enqueue ran since, so the
        // wait is the whole budget (no second clock read through a cold helper).
        let answer = rx.recv_timeout(WAIT);

        drop(waiting);
        answer.unwrap_or_else(|_| {
            Err(refused_fmt(
                ERROR_KIND_INTERNAL,
                format_args!("secret module '{name}' did not answer its resolve on the disk lane"),
            ))
        })
    }
}

impl Opened {
    fn resolve_here(&self, settings: &[u8]) -> Result<SecretValue<Vec<u8>>, SecretRefused> {
        let name = self.plugin.name();
        let mut held = SecretValue::zeroed(FIRST_SECRET_CAP);
        let (buf, cap) = held.lend_mut();
        let mut f = Frame::new(
            resolve_in(blob(settings, BLOB_JSON, 0), buf, cap),
            resolve_out(),
        );
        let mut c = self.plugin.call(slot::RESOLVE, &mut f);
        let mut recalled = None;
        if let Some(token) = c.recall.take() {
            held = SecretValue::zeroed(regrown(&f.out));
            let (buf, cap) = held.lend_mut();
            f.input.secret_buf = buf;
            f.input.secret_cap = cap;
            f.out = resolve_out();
            c = self.plugin.recall(token, slot::RESOLVE, &mut f);
            recalled = Some(cap);
        }
        if recalled.is_some_and(|lent| short_again(c.outcome, &f.out, lent)) {
            return Err(changed_size(name));
        }
        match c.outcome {
            Outcome::Ready => {
                held.keep(f.out.secret.len);
                Ok(held)
            }
            Outcome::Failed | Outcome::Refused => Err(refused(
                f.out.error_kind,
                answer_text(
                    c.error.as_deref(),
                    format_args!("secret module '{name}' failed to resolve"),
                ),
            )),
            o => Err(refused(
                ERROR_KIND_INTERNAL,
                answer_text(
                    c.error.as_deref(),
                    format_args!("secret module '{name}' answered {o:?} to resolve"),
                ),
            )),
        }
    }
}

impl Drop for Opened {
    fn drop(&mut self) {
        if let Some(schedule) = self
            .schedule
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            schedule.abort();
        }
        lifecycle::close(&self.plugin);
    }
}

impl LoadedSecret {
    /// `refresh` this instance with `settings` and the lent `secrets`, under its next generation.
    fn refresh_in_place(
        &self,
        relending: &Relending,
        settings: &[u8],
        secrets: &[SecretValue<Vec<u8>>],
    ) -> Called {
        let blobs: Vec<Blob> = match self.dispatcher.seal() {
            Some(seal) => secret_blobs(secrets, seal),
            None => Vec::new(),
        };
        let generation = relending
            .generation
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        let mut f = Frame::new(
            busbar_contract::abi::mechanism::lifecycle::RefreshIn {
                head: in_head(),
                generation,
                settings: blob(settings, BLOB_JSON, 0),
                secrets: if blobs.is_empty() {
                    std::ptr::null()
                } else {
                    blobs.as_ptr()
                },
                secrets_len: blobs.len(),
            },
            out_head(),
        );
        self.opened.plugin.call(life::REFRESH, &mut f)
    }
}

impl SecretCalls for LoadedSecret {
    fn relends(&self) -> bool {
        self.relending.is_some()
    }

    fn relend(
        &self,
        resolve: &dyn Fn(&SecretRef) -> Result<SecretValue<Vec<u8>>, String>,
    ) -> Result<SecretRelent, RelendRefused> {
        let Some(relending) = &self.relending else {
            return Ok(SecretRelent::Unchanged);
        };
        let spec = &relending.spec;
        let refused = |cause, text| RelendRefused { cause, text };
        let (remaining, secrets) = spec
            .settings
            .lend_references(&spec.keys, &spec.sugars, &spec.module, resolve)
            .map_err(|text| refused(RelendCause::Unresolvable, text))?;
        let Some(seal) = self.dispatcher.seal() else {
            return Err(refused(
                RelendCause::Unresolvable,
                "re-lending requires the host settings seal".into(),
            ));
        };
        let fingerprint = lent_fingerprint(&secrets, seal);
        let unchanged = busbar_contract::redacted::constant_time_eq(
            &*relending
                .fingerprint
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
            &fingerprint,
        );
        if unchanged {
            return Ok(SecretRelent::Unchanged);
        }
        let encoded = remaining
            .encode()
            .map_err(|e| refused(RelendCause::Unresolvable, encode_refused(&e)))?;
        let bytes = encoded.expose(seal);
        let called = self.refresh_in_place(relending, bytes, &secrets);
        let _lease = AnswerLease::new(&self.opened.plugin, called.lease);
        match called.outcome {
            Outcome::Ready => {
                *relending
                    .fingerprint
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = fingerprint;
                Ok(SecretRelent::Refreshed)
            }
            Outcome::Refused
                if called.error.as_deref()
                    == Some(busbar_contract::abi::sdk::life::NOT_REFRESHED.as_bytes()) =>
            {
                spec.open(bytes, &secrets)
                    .map(|opened| SecretRelent::Reopened(Arc::new(opened)))
                    .map_err(|text| refused(RelendCause::ReopenFailed, text))
            }
            outcome => Err(refused(
                RelendCause::Refused,
                lifecycle::why(outcome, called.error),
            )),
        }
    }

    fn resolve(&self, settings: &[u8]) -> Result<SecretValue<Vec<u8>>, SecretRefused> {
        let name = self.name();
        if !matches!(self.disk, Disk::No) {
            return Err(refused_fmt(
                ERROR_KIND_DENIED,
                format_args!("secret module '{name}': {RESOLVE_OFF_CONFIG_TIME}"),
            ));
        }
        let plugin = &self.opened.plugin;
        let workers = self.dispatcher.workers().max(1);
        let worker = self.next_worker.fetch_add(1, Ordering::Relaxed) % workers;
        let Some(ticket) = self.dispatcher.mint(worker) else {
            return Err(refused_fmt(
                ERROR_KIND_INTERNAL,
                format_args!("secret module '{name}' could not be called: no ticket"),
            ));
        };

        let deadline = now_ns().saturating_add(CALL_DEADLINE.as_nanos() as u64);
        let mut cap = FIRST_SECRET_CAP;
        let mut first = true;
        let (done, lending) = loop {
            let (lending, input) = Lending::new(settings, cap);
            let done = self
                .dispatcher
                .submit_lent(
                    plugin,
                    ticket,
                    slot::RESOLVE,
                    Frame::new(input, resolve_out()),
                    DeadlineClass::Call,
                    deadline,
                    Arc::clone(&lending) as crate::dispatch::Lent,
                )
                .wait(WAIT);
            match done {
                Some(d) if d.short && first => {
                    first = false;
                    cap = d.frame.as_ref().map_or(cap, |f| regrown(&f.out));
                }
                d => break (d, lending),
            }
        };
        self.dispatcher.recycle(ticket);
        let Some(done) = done else {
            return Err(refused_fmt(
                ERROR_KIND_INTERNAL,
                format_args!("secret module '{name}' did not answer its resolve"),
            ));
        };
        if !first
            && done
                .frame
                .as_ref()
                .is_some_and(|f| short_again(done.outcome, &f.out, cap))
        {
            return Err(changed_size(name));
        }
        match (done.outcome, done.frame.as_ref()) {
            (Outcome::Ready, Some(f)) => Ok(lending.take(f.out.secret.len)),
            (Outcome::Failed | Outcome::Refused, f) => Err(refused(
                f.map_or(ERROR_KIND_INTERNAL, |f| f.out.error_kind),
                answer_text(
                    done.error.as_deref(),
                    format_args!("secret module '{name}' failed to resolve"),
                ),
            )),
            (o, _) => Err(refused(
                ERROR_KIND_INTERNAL,
                answer_text(
                    done.error.as_deref(),
                    format_args!("secret module '{name}' answered {o:?} to resolve"),
                ),
            )),
        }
    }

    fn resolve_at_config(
        &self,
        settings: &[u8],
        _scope: &ConfigScope,
    ) -> Result<SecretValue<Vec<u8>>, SecretRefused> {
        match self.disk {
            Disk::No => self.resolve(settings),
            Disk::Lane(lane) => self.resolve_on_lane(lane, settings),
            Disk::Unwired => Err(refused_fmt(
                ERROR_KIND_UNAVAILABLE,
                format_args!(
                    "secret module '{}' reads the disk and the host wired no disk lane",
                    self.name()
                ),
            )),
        }
    }
}

pub struct SecretRows {
    dispatcher: fn() -> Arc<Dispatcher>,

    conns: fn() -> Option<AdmissionAuthority>,

    logs: Option<fn() -> PluginLogConfig>,
    pub(crate) linked: Vec<Candidate>,
    pub(crate) dropped: RwLock<Vec<Candidate>>,

    shared: OpenOnce<String, LoadedSecret>,

    disk_run: Option<DiskRun>,

    pub(crate) checkers: Mutex<Checkers>,
}

#[derive(Default)]
pub(crate) struct Checkers {
    pub(crate) generation: Arc<()>,
    pub(crate) plugins: foldhash::HashMap<CheckerKey, Arc<Plugin<Secret>>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CheckerKey {
    Linked(usize),
    Dropped(usize),
}

/// The candidates' names, listed as a `Debug` list without collecting them.
struct CandidateNames<'a>(&'a [Candidate]);

impl std::fmt::Debug for CandidateNames<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|c| &c.name))
            .finish()
    }
}

impl std::fmt::Debug for SecretRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretRows")
            .field("linked", &CandidateNames(&self.linked))
            .field(
                "dropped",
                &CandidateNames(&self.dropped.read().unwrap_or_else(PoisonError::into_inner)),
            )
            .finish_non_exhaustive()
    }
}

impl SecretRows {
    pub fn new(
        dispatcher: fn() -> Arc<Dispatcher>,
        conns: fn() -> Option<AdmissionAuthority>,
    ) -> Self {
        Self {
            dispatcher,
            conns,
            logs: None,
            linked: Vec::new(),
            dropped: RwLock::new(Vec::new()),
            shared: OpenOnce::new(),
            disk_run: None,
            checkers: Mutex::default(),
        }
    }

    #[must_use]
    pub fn with_disk_lane(mut self, run: DiskRun) -> Self {
        self.disk_run = Some(run);
        self
    }

    pub fn declare_linked(&mut self, door: DoorFn, json: &str) -> Result<&mut Self, String> {
        let name = Candidate::linked(door)?.name;
        let declares = crate::sign::Declares::from_declares_json(json.as_bytes())
            .map_err(|e| declares_unread(&name, &e))?;
        let row = self.declared_row(&name)?;
        row.disk = declares.disk;
        Ok(self)
    }

    fn loader(&self) -> Loader {
        Loader {
            dispatcher: self.dispatcher,
            conns: self.conns,
            logs: self.logs,
            disk_run: self.disk_run,
        }
    }

    fn placed(&self, c: &Candidate, opened: LoadedSecret) -> LoadedSecret {
        self.loader().placed(c, opened)
    }

    #[must_use]
    pub fn with_logs(mut self, logs: fn() -> PluginLogConfig) -> Self {
        self.logs = Some(logs);
        self
    }

    pub fn link(&mut self, door: DoorFn) -> Result<&mut Self, String> {
        let c = Candidate::linked(door)?;
        if c.kind != KindCode::Secret {
            return Err(not_a_secret_door(&c.name, c.kind));
        }
        self.linked.push(c);

        if let Err(e) = crate::boot::sugars_of(&self.linked) {
            self.linked.pop();
            return Err(e);
        }
        Ok(self)
    }

    /// [`Self::link`], the row also answering to `former`: a word that is another linked secret's
    /// name or word is a claim conflict, and nothing is linked.
    pub fn link_with_former(
        &mut self,
        door: DoorFn,
        former: &[String],
    ) -> Result<&mut Self, String> {
        self.link(door)?;
        if former.is_empty() {
            return Ok(self);
        }
        if let Some(row) = self.linked.pop() {
            self.linked.push(row.answering(former));
        }
        if let Err(e) = crate::boot::one_owner(&self.linked) {
            self.linked.pop();
            return Err(e);
        }
        Ok(self)
    }

    pub fn with_former_names(
        &mut self,
        former_of: impl Fn(&str) -> Vec<String>,
    ) -> Result<&mut Self, String> {
        for c in &mut self.linked {
            *c = c.clone().answering_former(&former_of);
        }
        crate::boot::one_owner(&self.linked)?;
        Ok(self)
    }

    pub fn admit_dropped(
        &self,
        candidates: impl IntoIterator<Item = Candidate>,
    ) -> Result<(), String> {
        let secrets = self.judge_dropped(candidates)?;
        let all = self.with_linked(&secrets);
        for line in crate::boot::both_doors(&all) {
            tracing::info!("{line}");
        }
        self.set_dropped(secrets);
        Ok(())
    }

    pub fn judge_dropped(
        &self,
        candidates: impl IntoIterator<Item = Candidate>,
    ) -> Result<Vec<Candidate>, String> {
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: judging dropped secrets checks them with the linked ones once"
        )]
        let secrets: Vec<Candidate> = candidates
            .into_iter()
            .filter(|c| c.kind == KindCode::Secret)
            .collect();
        let all = self.with_linked(&secrets);
        crate::boot::one_owner(&all)?;
        crate::boot::sugars_of(&all)?;
        Ok(secrets)
    }

    /// The secret shorthand the linked rows and `candidates` declare together, judged exactly as
    /// [`Self::judge_dropped`] judges them (one owner per word, name and alias). Pure: the live
    /// dropped-in set, its checkers and the axis are untouched. A read's grammar comes from here;
    /// only admission ([`Self::admit_dropped`]) puts a set on the axis.
    pub fn grammar_of(
        &self,
        candidates: impl IntoIterator<Item = Candidate>,
    ) -> Result<busbar_contract::secret_ref::Sugars, String> {
        let secrets = self.judge_dropped(candidates)?;
        crate::boot::sugars_of(&self.with_linked(&secrets))
    }

    /// A read-scoped secret axis over the linked rows and `candidates`, which were judged but never
    /// admitted ([`SecretView`]). Its checkers are its own and are dropped with it.
    #[must_use]
    pub fn view(&self, candidates: impl IntoIterator<Item = Candidate>) -> SecretView<'_> {
        SecretView {
            rows: self,
            dropped: candidates
                .into_iter()
                .filter(|c| c.kind == KindCode::Secret)
                .collect(),
            checkers: Mutex::default(),
        }
    }

    pub fn set_dropped(&self, candidates: impl IntoIterator<Item = Candidate>) {
        let retired = {
            let mut dropped = self.dropped.write().unwrap_or_else(PoisonError::into_inner);
            let mut checkers = self.checkers.lock().unwrap_or_else(PoisonError::into_inner);
            let retired = std::mem::take(&mut *dropped);
            dropped.extend(
                candidates
                    .into_iter()
                    .filter(|c| c.kind == KindCode::Secret),
            );
            let checkers = std::mem::take(&mut *checkers);
            (retired, checkers)
        };

        drop(retired);
    }

    /// The live dropped-in set, for a caller that may need to put it back
    /// ([`Self::restore_if_changed`]).
    #[must_use]
    pub fn dropped(&self) -> Vec<Candidate> {
        crate::cold::secret_calls::dropped_copy(self)
    }

    /// Put `snapshot` back as the live dropped-in set if the live set differs from it by name,
    /// version or image. An unchanged set is left alone, and so are its cached checkers. Returns
    /// whether the set was replaced.
    pub fn restore_if_changed(&self, snapshot: Vec<Candidate>) -> bool {
        let same = crate::cold::secret_calls::same_set(
            &self.dropped.read().unwrap_or_else(PoisonError::into_inner),
            &snapshot,
        );
        if !same {
            self.set_dropped(snapshot);
        }
        !same
    }

    pub(crate) fn load(&self, c: &Candidate, label: &str) -> Result<Plugin<Secret>, String> {
        self.loader().load(c, label)
    }

    fn secret_refs(c: &Candidate) -> Result<Vec<String>, String> {
        busbar_contract::abi::mechanism::rendering::read(&c.stated)
            .map(|r| r.secret_refs)
            .map_err(|e| statement_unread(&c.name, &e))
    }
}

impl SecretAxis for SecretRows {
    fn sugars(&self) -> busbar_contract::secret_ref::Sugars {
        crate::boot::sugars_of(&self.all_candidates()).unwrap_or_default()
    }

    fn answers(&self, module: &str) -> bool {
        self.find_candidate(module).is_some()
    }

    fn check(
        &self,
        module: &str,
        settings: &busbar_contract::plugin_settings::Settings,
    ) -> Result<(), Vec<String>> {
        let Some(plugin) = self.checker(module).map_err(|e| vec![e])? else {
            return Ok(());
        };
        let held = settings.encode().map_err(|_| unencodable_settings())?;
        let dispatcher = (self.dispatcher)();
        let seal = dispatcher.seal().ok_or_else(unsealed_check)?;
        check(&plugin, held.expose(seal))
    }

    fn linked(&self, module: &str) -> bool {
        self.answers_linked(module)
    }

    fn shared(&self, module: &str) -> Result<Arc<dyn SecretCalls>, String> {
        let c = self.linked_candidate(module)?;

        let instance = label(module);
        let (s, _) = self.shared.get_or_open(&c.name, || {
            LoadedSecret::open(self.load(c, &instance)?, (self.dispatcher)(), &[], &[])
                .map(|opened| self.placed(c, opened))
        })?;
        Ok(s)
    }

    fn open(
        &self,
        module: &str,
        settings: Option<&busbar_contract::plugin_settings::Settings>,
        resolve: &dyn Fn(&SecretRef) -> Result<SecretValue<Vec<u8>>, String>,
    ) -> Result<Arc<dyn SecretCalls>, String> {
        let c = self
            .find_candidate(module)
            .ok_or_else(|| unanswered(module))?;
        let keys = Self::secret_refs(&c)?;
        let dispatcher = (self.dispatcher)();
        let seal = dispatcher
            .seal()
            .ok_or("secret module opening requires the host settings seal")?;
        let Some(settings) = settings.filter(|_| !keys.is_empty()) else {
            let bytes = match settings {
                Some(settings) => {
                    let (remaining, _) =
                        settings.lend_references(&keys, &self.sugars(), module, resolve)?;
                    remaining.encode().map_err(|error| encode_refused(&error))?
                }
                None => SecretValue::default(),
            };
            let opened = LoadedSecret::open(
                self.load(&c, &label(module))?,
                Arc::clone(&dispatcher),
                bytes.expose(seal),
                &[],
            )?;
            return Ok(Arc::new(self.placed(&c, opened)));
        };
        // The instance lends its own references: keep what re-lending them needs, pinned to THIS
        // candidate (never the global dropped set a later admission replaces), so a rotated
        // credential reaches the plugin without a reload.
        let spec = Arc::new(RelendSpec {
            module: module_name(module),
            label: label(module),
            settings: settings.clone(),
            keys,
            sugars: self.sugars(),
            candidate: c,
            loader: self.loader(),
        });
        let (remaining, secrets) =
            spec.settings
                .lend_references(&spec.keys, &spec.sugars, module, resolve)?;
        let bytes = remaining.encode().map_err(|error| encode_refused(&error))?;
        Ok(Arc::new(spec.open(bytes.expose(seal), &secrets)?))
    }
}

/// A read-scoped secret axis: the linked rows plus a dropped-in set a read judged and never
/// admitted (`--validate`'s view of what process start judged). It answers and checks references
/// to those modules, loading each dropped module's checker at most once into its own cache, and
/// opens no dropped-in instance. The live axis and its checker cache are untouched.
pub struct SecretView<'a> {
    rows: &'a SecretRows,
    dropped: Vec<Candidate>,
    checkers: Mutex<std::collections::BTreeMap<usize, Arc<Plugin<Secret>>>>,
}

impl std::fmt::Debug for SecretView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretView")
            .field("rows", self.rows)
            .field("dropped", &CandidateNames(&self.dropped))
            .finish_non_exhaustive()
    }
}

impl SecretView<'_> {
    fn dropped_answering(&self, module: &str) -> Option<(usize, &Candidate)> {
        if self.rows.answers_linked(module) {
            return None;
        }
        self.dropped
            .iter()
            .enumerate()
            .find(|(_, c)| c.answers(module))
    }

    fn checker(
        &self,
        at: usize,
        c: &Candidate,
        module: &str,
    ) -> Result<Arc<Plugin<Secret>>, String> {
        let mut held = self.checkers.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(plugin) = held.get(&at) {
            return Ok(Arc::clone(plugin));
        }
        let plugin = Arc::new(self.rows.load(c, &format!("{}.check", label(module)))?);
        held.insert(at, Arc::clone(&plugin));
        Ok(plugin)
    }
}

impl SecretAxis for SecretView<'_> {
    fn sugars(&self) -> busbar_contract::secret_ref::Sugars {
        crate::boot::sugars_of(&self.rows.with_linked(&self.dropped)).unwrap_or_default()
    }

    fn answers(&self, module: &str) -> bool {
        self.rows.answers_linked(module) || self.dropped_answering(module).is_some()
    }

    fn check(
        &self,
        module: &str,
        settings: &busbar_contract::plugin_settings::Settings,
    ) -> Result<(), Vec<String>> {
        let Some((at, c)) = self.dropped_answering(module) else {
            return if self.rows.answers_linked(module) {
                SecretAxis::check(self.rows, module, settings)
            } else {
                Ok(())
            };
        };
        let plugin = self.checker(at, c, module).map_err(|e| vec![e])?;
        let held = settings.encode().map_err(|_| unencodable_settings())?;
        let dispatcher = (self.rows.dispatcher)();
        let seal = dispatcher.seal().ok_or_else(unsealed_check)?;
        check(&plugin, held.expose(seal))
    }

    fn linked(&self, module: &str) -> bool {
        self.rows.answers_linked(module)
    }

    fn shared(&self, module: &str) -> Result<Arc<dyn SecretCalls>, String> {
        self.rows.shared(module)
    }

    fn open(
        &self,
        module: &str,
        settings: Option<&busbar_contract::plugin_settings::Settings>,
        resolve: &dyn Fn(&SecretRef) -> Result<SecretValue<Vec<u8>>, String>,
    ) -> Result<Arc<dyn SecretCalls>, String> {
        if self.rows.answers_linked(module) {
            return self.rows.open(module, settings, resolve);
        }
        Err(format!(
            "secret module '{module}' was judged by this read but not admitted: a read-scoped \
             view opens no dropped-in module"
        ))
    }
}

#[cfg(test)]
#[path = "tests/secret_calls_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/secret_disk_tests.rs"]
mod disk_tests;

#[cfg(test)]
#[path = "tests/secret_relend_tests.rs"]
mod relend_tests;
