// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use crate::open_once::OpenOnce;
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{
    Blob, DeadlineClass, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
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

use crate::boot::Candidate;
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::lifecycle::{self, blob, open_frame, AnswerLease};
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
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: names the secret module that could not be loaded"
        )]
        let sink: Arc<dyn EnvelopeSink> = match self.logs {
            Some(logs) => Arc::new(
                logs()
                    .sink(label, KindCode::Secret, Arc::new(NoSink))
                    .map_err(|e| format!("secret module '{}' could not be loaded: {e}", c.name))?,
            ),
            None => Arc::new(NoSink),
        };
        // busbar:expect(bp::into_alloc, reason = "boot: a loaded secret instance keeps its label")
        let bind = Bind {
            instance: Arc::from(label),
            max_inflight_cap: MAX_INFLIGHT_CAP,
            sink,
            dispatcher: (self.dispatcher)().adopter(),

            conns: ConnTable::serving((self.conns)()),
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: names the secret module that could not be loaded"
        )]
        let loaded = crate::boot::open_candidate::<Secret>(c, bind)
            .map_err(|e| format!("secret module '{}' could not be loaded: {e}", c.name));
        loaded
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
    settings: zeroize::Zeroizing<Vec<u8>>,
    held: Mutex<SecretValue<Vec<u8>>>,
}

impl Lending {
    fn new(settings: &[u8], cap: usize) -> (Arc<Self>, ResolveIn) {
        let mut held = SecretValue::zeroed(cap);
        let (buf, cap) = held.lend_mut();
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a secret reference resolves when config is loaded; the lent settings outlive a timed-out wait"
        )]
        let settings = zeroize::Zeroizing::new(settings.to_vec());
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
    #[expect(
        clippy::disallowed_methods,
        reason = "config: lists why the secret module refused a reference at config time"
    )]
    let checked = match c.outcome {
        Outcome::Ready | Outcome::Refused => Ok(()),
        Outcome::Failed => {
            let text = c.error.as_deref().unwrap_or_default();
            if busbar_contract::abi::mechanism::lifecycle::check_validate_refusal(text).is_err() {
                return Err(vec![format!(
                    "secret module '{name}' refused the reference without saying why"
                )]);
            }
            Err(String::from_utf8_lossy(text)
                .split('\n')
                .map(str::to_string)
                .collect())
        }
        o => Err(vec![format!(
            "secret module '{name}' answered {o:?} to check the reference"
        )]),
    };
    checked
}

fn refused(error_kind: u32, text: String) -> SecretRefused {
    SecretRefused { error_kind, text }
}

/// A refusal whose text is formatted here, on the refusal path only.
fn refused_fmt(error_kind: u32, text: std::fmt::Arguments<'_>) -> SecretRefused {
    #[expect(
        clippy::disallowed_methods,
        reason = "error: names the secret module whose resolve was refused"
    )]
    let text = format!("{text}");
    refused(error_kind, text)
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

/// The plugin's own refusal text, or the fallback, formatted only when it is the answer.
fn answer_text(error: Option<&[u8]>, fallback: std::fmt::Arguments<'_>) -> String {
    #[expect(
        clippy::disallowed_methods,
        reason = "error: the text of a refused secret resolve"
    )]
    let text = match error.filter(|e| !e.is_empty()) {
        Some(e) => String::from_utf8_lossy(e).into_owned(),
        None => format!("{fallback}"),
    };
    text
}

/// What an OPEN crossing borrows, owned for as long as the dispatcher may still read it (a PENDING
/// open is resumed later, and an open that outlives its wait is finished or cancelled by the
/// dispatcher, never against freed memory).
struct OpenLent {
    settings: zeroize::Zeroizing<Vec<u8>>,
    _secrets: Vec<zeroize::Zeroizing<Vec<u8>>>,
    blobs: Vec<Blob>,
}

// SAFETY: every blob pointer borrows an immutable allocation this value owns.
unsafe impl Send for OpenLent {}
// SAFETY: as above; nothing in it is mutated after construction.
unsafe impl Sync for OpenLent {}

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
        let owned: Vec<zeroize::Zeroizing<Vec<u8>>> = match (secrets.is_empty(), dispatcher.seal())
        {
            (true, _) => Vec::new(),
            (false, Some(seal)) => secrets
                .iter()
                .map(|s| zeroize::Zeroizing::new(s.expose(seal).clone()))
                .collect(),
            (false, None) => {
                return Err(format!(
                    "plugin '{}' open failed: its secret material is revealed only on a \
                         dispatcher the host lent its seal",
                    plugin.name()
                ));
            }
        };
        let blobs = owned
            .iter()
            .map(|s| blob(s, BLOB_OCTETS, BLOB_SECRET))
            .collect();
        let lent = Arc::new(OpenLent {
            settings: zeroize::Zeroizing::new(settings.to_vec()),
            _secrets: owned,
            blobs,
        });
        let mut f = open_frame(blob(&lent.settings, BLOB_JSON, 0));
        if !lent.blobs.is_empty() {
            f.input.secrets = lent.blobs.as_ptr();
            f.input.secrets_len = lent.blobs.len();
        }
        let Some(ticket) = dispatcher.mint(0) else {
            return Err(format!(
                "plugin '{}' open failed: no ticket to open it on",
                plugin.name()
            ));
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
            return Err(format!(
                "secret module '{}' did not complete its open within {} s",
                plugin.name(),
                WAIT.as_secs()
            ));
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
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a disk-lane resolve runs at config time only, off this thread"
        )]
        let (name, owned) = (self.name().to_string(), settings.to_vec());
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
        // busbar:expect(bp::clock_repeat, reason = "config: a config-time disk-lane resolve waits out the rest of its budget")
        let left = deadline.saturating_duration_since(instant_at(now_ns()));
        let answer = rx.recv_timeout(left);

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
            Some(seal) => secrets
                .iter()
                .map(|s| blob(s.expose(seal), BLOB_OCTETS, BLOB_SECRET))
                .collect(),
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
            .map_err(|e| refused(RelendCause::Unresolvable, e.to_string()))?;
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
    linked: Vec<Candidate>,
    dropped: RwLock<Vec<Candidate>>,

    shared: OpenOnce<String, LoadedSecret>,

    disk_run: Option<DiskRun>,

    checkers: Mutex<Checkers>,
}

#[derive(Default)]
struct Checkers {
    generation: Arc<()>,
    plugins: foldhash::HashMap<CheckerKey, Arc<Plugin<Secret>>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum CheckerKey {
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
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: a linked secret's declares section did not read"
        )]
        let declares = crate::sign::Declares::from_declares_json(json.as_bytes())
            .map_err(|e| format!("linked secret '{name}': its declares section: {e}"))?;
        // busbar:expect(bp::state_scan, reason = "boot: a linked secret's declares are matched to its row once, at link time")
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: a linked secret declares, but no linked row is it"
        )]
        let row = self
            .linked
            .iter_mut()
            .find(|c| c.name == name)
            .ok_or_else(|| format!("linked secret '{name}' declares, but no linked row is it"))?;
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

    fn label(module: &str) -> String {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a secret module's instance label, named when config opens or checks it"
        )]
        let label = format!("secrets.{module}");
        label
    }

    pub fn link(&mut self, door: DoorFn) -> Result<&mut Self, String> {
        let c = Candidate::linked(door)?;
        if c.kind != KindCode::Secret {
            #[expect(
                clippy::disallowed_methods,
                reason = "boot: a linked door of another kind was offered as a secret"
            )]
            let refused = format!("`{}` is a {:?} door, not a secret one", c.name, c.kind);
            return Err(refused);
        }
        self.linked.push(c);

        if let Err(e) = crate::boot::sugars_of(&self.linked) {
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
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: admitting dropped secrets checks them with the linked ones once"
        )]
        let all: Vec<Candidate> = self
            .linked
            .iter()
            .cloned()
            .chain(secrets.iter().cloned())
            .collect();
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
        let (secrets, all) = {
            let secrets: Vec<Candidate> = candidates
                .into_iter()
                .filter(|c| c.kind == KindCode::Secret)
                .collect();
            let all: Vec<Candidate> = self
                .linked
                .iter()
                .cloned()
                .chain(secrets.iter().cloned())
                .collect();
            (secrets, all)
        };
        crate::boot::one_owner(&all)?;
        crate::boot::sugars_of(&all)?;
        Ok(secrets)
    }

    pub fn set_dropped(&self, candidates: impl IntoIterator<Item = Candidate>) {
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: the admitted dropped secrets are set once per registry load"
        )]
        let secrets = candidates
            .into_iter()
            .filter(|c| c.kind == KindCode::Secret)
            .collect();
        let retired = {
            let mut dropped = self.dropped.write().unwrap_or_else(PoisonError::into_inner);
            let mut checkers = self.checkers.lock().unwrap_or_else(PoisonError::into_inner);
            let candidates = std::mem::replace(&mut *dropped, secrets);
            let checkers = std::mem::take(&mut *checkers);
            (candidates, checkers)
        };

        drop(retired);
    }

    fn checker(&self, module: &str) -> Result<Option<Arc<Plugin<Secret>>>, String> {
        let (key, candidate, generation) = {
            let dropped = self.dropped.read().unwrap_or_else(PoisonError::into_inner);
            let checkers = self.checkers.lock().unwrap_or_else(PoisonError::into_inner);
            let Some((key, candidate)) = self
                .linked
                .iter()
                .enumerate()
                .find(|(_, c)| c.answers(module))
                .map(|(i, c)| (CheckerKey::Linked(i), c))
                .or_else(|| {
                    dropped
                        .iter()
                        .enumerate()
                        .find(|(_, c)| c.answers(module))
                        .map(|(i, c)| (CheckerKey::Dropped(i), c))
                })
            else {
                return Ok(None);
            };
            if let Some(plugin) = checkers.plugins.get(&key) {
                return Ok(Some(Arc::clone(plugin)));
            }
            (key, candidate.clone(), Arc::clone(&checkers.generation))
        };

        #[expect(
            clippy::disallowed_methods,
            reason = "config: a secret module's checker is loaded once per registry generation"
        )]
        let label = format!("{}.check", Self::label(module));
        let loaded = Arc::new(self.load(&candidate, &label)?);
        let plugin = {
            let mut checkers = self.checkers.lock().unwrap_or_else(PoisonError::into_inner);
            if Arc::ptr_eq(&generation, &checkers.generation) {
                Arc::clone(
                    checkers
                        .plugins
                        .entry(key)
                        .or_insert_with(|| Arc::clone(&loaded)),
                )
            } else {
                Arc::clone(&loaded)
            }
        };
        Ok(Some(plugin))
    }

    fn find(&self, module: &str) -> Option<Candidate> {
        // busbar:expect(bp::state_scan, reason = "config: a configured secret module is matched to its candidate when config is read")
        if let Some(c) = self.linked.iter().find(|c| c.answers(module)) {
            return Some(c.clone());
        }
        let dropped = self.dropped.read().unwrap_or_else(PoisonError::into_inner);
        // busbar:expect(bp::state_scan, reason = "config: a configured secret module is matched to its candidate when config is read")
        dropped.iter().find(|c| c.answers(module)).cloned()
    }

    fn load(&self, c: &Candidate, label: &str) -> Result<Plugin<Secret>, String> {
        self.loader().load(c, label)
    }

    fn secret_refs(c: &Candidate) -> Result<Vec<String>, String> {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a secret module's Statement did not read back"
        )]
        let refs = busbar_contract::abi::mechanism::rendering::read(&c.stated)
            .map(|r| r.secret_refs)
            .map_err(|e| {
                format!(
                    "secret module '{}': its Statement does not read back (byte {}: {})",
                    c.name, e.at, e.what
                )
            });
        refs
    }
}

impl SecretAxis for SecretRows {
    fn sugars(&self) -> busbar_contract::secret_ref::Sugars {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the secret sugars are gathered when config is read"
        )]
        let all: Vec<Candidate> = self
            .linked
            .iter()
            .cloned()
            .chain(
                self.dropped
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .iter()
                    .cloned(),
            )
            .collect();

        crate::boot::sugars_of(&all).unwrap_or_default()
    }

    fn answers(&self, module: &str) -> bool {
        self.find(module).is_some()
    }

    fn check(
        &self,
        module: &str,
        settings: &busbar_contract::plugin_settings::Settings,
    ) -> Result<(), Vec<String>> {
        let Some(plugin) = self.checker(module).map_err(|e| vec![e])? else {
            return Ok(());
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a secret reference's settings did not render for checking"
        )]
        let held = settings
            .encode()
            .map_err(|_| vec!["cannot encode source settings".to_owned()])?;
        let dispatcher = (self.dispatcher)();
        #[expect(
            clippy::disallowed_methods,
            reason = "config: checking a secret reference needs the host settings seal"
        )]
        let seal = dispatcher
            .seal()
            .ok_or_else(|| vec!["source validation requires the host settings seal".to_owned()])?;
        check(&plugin, held.expose(seal))
    }

    fn linked(&self, module: &str) -> bool {
        // busbar:expect(bp::state_scan, reason = "config: whether config names a linked secret module")
        self.linked.iter().any(|c| c.answers(module))
    }

    fn shared(&self, module: &str) -> Result<Arc<dyn SecretCalls>, String> {
        // busbar:expect(bp::state_scan, reason = "config: a shared secret module is matched when config opens it")
        #[expect(
            clippy::disallowed_methods,
            reason = "config: names a configured secret module no linked plugin answers to"
        )]
        let c = self
            .linked
            .iter()
            .find(|c| c.answers(module))
            .ok_or_else(|| format!("no linked secret module answers to '{module}'"))?;

        let label = Self::label(module);
        let (s, _) = self.shared.get_or_open(&c.name, || {
            LoadedSecret::open(self.load(c, &label)?, (self.dispatcher)(), &[], &[])
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
        #[expect(
            clippy::disallowed_methods,
            reason = "config: names a configured secret module no plugin answers to"
        )]
        let c = self
            .find(module)
            .ok_or_else(|| format!("no secret module answers to '{module}'"))?;
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
                    remaining.encode().map_err(|error| error.to_string())?
                }
                None => SecretValue::default(),
            };
            let opened = LoadedSecret::open(
                self.load(&c, &Self::label(module))?,
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
            module: module.to_string(),
            label: Self::label(module),
            settings: settings.clone(),
            keys,
            sugars: self.sugars(),
            candidate: c,
            loader: self.loader(),
        });
        let (remaining, secrets) =
            spec.settings
                .lend_references(&spec.keys, &spec.sugars, module, resolve)?;
        let bytes = remaining.encode().map_err(|error| error.to_string())?;
        Ok(Arc::new(spec.open(bytes.expose(seal), &secrets)?))
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
