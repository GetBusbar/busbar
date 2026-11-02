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
use busbar_contract::conn::DeclaredConns;
use busbar_contract::redacted::Secret as SecretValue;
use busbar_contract::secret::{SecretAxis, SecretCalls, SecretRefused};
use busbar_contract::secret_ref::SecretRef;

use crate::boot::{Candidate, Origin};
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::lifecycle::{self, blob, open_frame, AnswerLease};
use crate::dispatch::{
    in_head, load_dropped_bytes, load_linked, now_ns, out_head, Bind, ConnTable, Dispatcher,
    EnvelopeSink, Frame, NoSink, Plugin, PluginLogConfig, NO_BLOB,
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
        if Instant::now() < self.deadline {
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
}

struct Opened {
    plugin: Plugin<Secret>,
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
    // settings-leak-lint: allow — NON-PROJECTION engine type: one resolve's settings bytes, lent to
    settings: Vec<u8>,
    held: Mutex<SecretValue<Vec<u8>>>,
}

impl Lending {
    fn new(settings: &[u8], cap: usize) -> (Arc<Self>, ResolveIn) {
        let mut held = SecretValue::zeroed(cap);
        let (buf, cap) = held.lend_mut();
        let lending = Arc::new(Self {
            settings: settings.to_vec(),
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
    }
}

fn refused(error_kind: u32, text: String) -> SecretRefused {
    SecretRefused { error_kind, text }
}

fn changed_size(name: &str) -> SecretRefused {
    refused(
        ERROR_KIND_UNAVAILABLE,
        format!(
            "secret module '{name}' could not resolve: the secret's value changed size between \
             the host's two reads; resolve it again"
        ),
    )
}

fn short_again(outcome: Outcome, out: &ResolveOut, lent: usize) -> bool {
    outcome == Outcome::Fault && out.needed > lent as u64
}

fn answer_text(error: Option<&[u8]>, fallback: String) -> String {
    error
        .map(|e| String::from_utf8_lossy(e).into_owned())
        .filter(|t| !t.is_empty())
        .unwrap_or(fallback)
}

impl LoadedSecret {
    pub fn open(
        plugin: Plugin<Secret>,
        dispatcher: Arc<Dispatcher>,
        settings: &[u8],
        secrets: &[SecretValue<Vec<u8>>],
    ) -> Result<Self, String> {
        let lent: Vec<Blob> = match (secrets.is_empty(), dispatcher.seal()) {
            (true, _) => Vec::new(),
            (false, Some(seal)) => secrets
                .iter()
                .map(|s| blob(s.expose(seal), BLOB_OCTETS, BLOB_SECRET))
                .collect(),
            (false, None) => {
                return Err(format!(
                    "plugin '{}' open failed: its secret material is revealed only on a \
                     dispatcher the host lent its seal",
                    plugin.name()
                ))
            }
        };
        let mut f = open_frame(blob(settings, BLOB_JSON, 0));
        f.input.secrets = lent.as_ptr();
        f.input.secrets_len = lent.len();
        let c = plugin.call(life::OPEN, &mut f);
        let opened = AnswerLease::new(&plugin, c.lease);
        if c.outcome != Outcome::Ready {
            return Err(c.open_failure(plugin.name()));
        }
        drop(opened);
        Ok(Self {
            opened: Arc::new(Opened { plugin }),
            dispatcher,
            next_worker: AtomicU32::new(0),
            disk: Disk::No,
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
        let name = self.name().to_string();
        let deadline = Instant::now() + WAIT;
        let opened = Arc::clone(&self.opened);
        let owned = settings.to_vec();
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
            refused(
                ERROR_KIND_UNAVAILABLE,
                format!("secret module '{name}' could not reach the host's disk lane: {e}"),
            )
        })?;
        let answer = rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));

        drop(waiting);
        answer.unwrap_or_else(|_| {
            Err(refused(
                ERROR_KIND_INTERNAL,
                format!("secret module '{name}' did not answer its resolve on the disk lane"),
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
                    format!("secret module '{name}' failed to resolve"),
                ),
            )),
            o => Err(refused(
                ERROR_KIND_INTERNAL,
                answer_text(
                    c.error.as_deref(),
                    format!("secret module '{name}' answered {o:?} to resolve"),
                ),
            )),
        }
    }
}

impl Drop for Opened {
    fn drop(&mut self) {
        lifecycle::close(&self.plugin);
    }
}

impl SecretCalls for LoadedSecret {
    fn resolve(&self, settings: &[u8]) -> Result<SecretValue<Vec<u8>>, SecretRefused> {
        let name = self.name();
        if !matches!(self.disk, Disk::No) {
            return Err(refused(
                ERROR_KIND_DENIED,
                format!("secret module '{name}': {RESOLVE_OFF_CONFIG_TIME}"),
            ));
        }
        let plugin = &self.opened.plugin;
        let workers = self.dispatcher.workers().max(1);
        let worker = self.next_worker.fetch_add(1, Ordering::Relaxed) % workers;
        let Some(ticket) = self.dispatcher.mint(worker) else {
            return Err(refused(
                ERROR_KIND_INTERNAL,
                format!("secret module '{name}' could not be called: no ticket"),
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
            return Err(refused(
                ERROR_KIND_INTERNAL,
                format!("secret module '{name}' did not answer its resolve"),
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
                    format!("secret module '{name}' failed to resolve"),
                ),
            )),
            (o, _) => Err(refused(
                ERROR_KIND_INTERNAL,
                answer_text(
                    done.error.as_deref(),
                    format!("secret module '{name}' answered {o:?} to resolve"),
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
            Disk::Unwired => Err(refused(
                ERROR_KIND_UNAVAILABLE,
                format!(
                    "secret module '{}' reads the disk and the host wired no disk lane",
                    self.name()
                ),
            )),
        }
    }
}

pub struct SecretRows {
    dispatcher: fn() -> Arc<Dispatcher>,

    conns: fn() -> Option<Arc<dyn DeclaredConns>>,

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
    plugins: std::collections::HashMap<CheckerKey, Arc<Plugin<Secret>>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum CheckerKey {
    Linked(usize),
    Dropped(usize),
}

impl std::fmt::Debug for SecretRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names = |c: &[Candidate]| c.iter().map(|c| c.name.clone()).collect::<Vec<_>>();
        f.debug_struct("SecretRows")
            .field("linked", &names(&self.linked))
            .field(
                "dropped",
                &names(&self.dropped.read().unwrap_or_else(PoisonError::into_inner)),
            )
            .finish_non_exhaustive()
    }
}

impl SecretRows {
    pub fn new(
        dispatcher: fn() -> Arc<Dispatcher>,
        conns: fn() -> Option<Arc<dyn DeclaredConns>>,
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
            .map_err(|e| format!("linked secret '{name}': its declares section: {e}"))?;
        let row = self
            .linked
            .iter_mut()
            .find(|c| c.name == name)
            .ok_or_else(|| format!("linked secret '{name}' declares, but no linked row is it"))?;
        row.disk = declares.disk;
        Ok(self)
    }

    fn placed(&self, c: &Candidate, opened: LoadedSecret) -> LoadedSecret {
        if c.disk {
            opened.reading_disk(self.disk_run)
        } else {
            opened
        }
    }

    #[must_use]
    pub fn with_logs(mut self, logs: fn() -> PluginLogConfig) -> Self {
        self.logs = Some(logs);
        self
    }

    fn label(module: &str) -> String {
        format!("secrets.{module}")
    }

    pub fn link(&mut self, door: DoorFn) -> Result<&mut Self, String> {
        let c = Candidate::linked(door)?;
        if c.kind != KindCode::Secret {
            return Err(format!(
                "`{}` is a {:?} door, not a secret one",
                c.name, c.kind
            ));
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
        crate::boot::one_owner(&all)?;
        crate::boot::sugars_of(&all)?;
        Ok(secrets)
    }

    pub fn set_dropped(&self, candidates: impl IntoIterator<Item = Candidate>) {
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

        let loaded = Arc::new(self.load(&candidate, &format!("{}.check", Self::label(module)))?);
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
        self.linked
            .iter()
            .find(|c| c.answers(module))
            .cloned()
            .or_else(|| {
                self.dropped
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .iter()
                    .find(|c| c.answers(module))
                    .cloned()
            })
    }

    fn load(&self, c: &Candidate, label: &str) -> Result<Plugin<Secret>, String> {
        let sink: Arc<dyn EnvelopeSink> = match self.logs {
            Some(logs) => Arc::new(
                logs()
                    .sink(label, KindCode::Secret, Arc::new(NoSink))
                    .map_err(|e| format!("secret module '{}' could not be loaded: {e}", c.name))?,
            ),
            None => Arc::new(NoSink),
        };
        let bind = Bind {
            instance: Arc::from(label),
            max_inflight_cap: MAX_INFLIGHT_CAP,
            sink,
            dispatcher: (self.dispatcher)().adopter(),

            conns: ConnTable::serving((self.conns)()),
        };
        match &c.origin {
            Origin::Linked(row) => load_linked::<Secret>(row, bind),
            Origin::Dropped { file, bytes } => {
                load_dropped_bytes::<Secret>(bytes, file, &c.stated, bind)
            }
        }
        .map_err(|e| format!("secret module '{}' could not be loaded: {e}", c.name))
    }

    fn secret_refs(c: &Candidate) -> Result<Vec<String>, String> {
        busbar_contract::abi::mechanism::rendering::read(&c.stated)
            .map(|r| r.secret_refs)
            .map_err(|e| {
                format!(
                    "secret module '{}': its Statement does not read back (byte {}: {})",
                    c.name, e.at, e.what
                )
            })
    }
}

impl SecretAxis for SecretRows {
    fn sugars(&self) -> busbar_contract::secret_ref::Sugars {
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

    fn check(&self, module: &str, settings: &serde_json::Value) -> Result<(), Vec<String>> {
        let Some(plugin) = self.checker(module).map_err(|e| vec![e])? else {
            return Ok(());
        };
        check(&plugin, settings.to_string().as_bytes())
    }

    fn linked(&self, module: &str) -> bool {
        self.linked.iter().any(|c| c.answers(module))
    }

    fn shared(&self, module: &str) -> Result<Arc<dyn SecretCalls>, String> {
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
        settings: &serde_json::Value,
        resolve: &dyn Fn(&SecretRef) -> Result<SecretValue<Vec<u8>>, String>,
    ) -> Result<Arc<dyn SecretCalls>, String> {
        let c = self
            .find(module)
            .ok_or_else(|| format!("no secret module answers to '{module}'"))?;
        let keys = Self::secret_refs(&c)?;
        if let Some(at) = busbar_contract::secret_fields::undeclared_reference(settings, &keys) {
            return Err(busbar_contract::secret_fields::undeclared_refusal(
                &format!("secrets.{module}.settings.{at}"),
                &c.name,
            ));
        }

        let reference = |at: &str, v: serde_json::Value| -> Result<SecretValue<Vec<u8>>, String> {
            let r = serde_json::from_value::<SecretRef>(v).map_err(
                crate::boot::not_a_reference(format!("secrets.{module}.settings.{at}")),
            )?;
            resolve(&r).map_err(|e| format!("secrets.{module}.settings.{at}: {e}"))
        };
        let mut lent_settings = settings.clone();
        let secrets = busbar_contract::secret_fields::lend(
            &mut lent_settings,
            &keys,
            true,
            |at, found| found.map_or(Ok(SecretValue::default()), |v| reference(at, v)),
            |at, found| reference(at, found),
        )?;
        let bytes = if lent_settings.is_null() {
            Vec::new()
        } else {
            lent_settings.to_string().into_bytes()
        };
        let opened = LoadedSecret::open(
            self.load(&c, &Self::label(module))?,
            (self.dispatcher)(),
            &bytes,
            &secrets,
        )?;
        Ok(Arc::new(self.placed(&c, opened)))
    }
}

#[cfg(test)]
#[path = "tests/secret_calls_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/secret_disk_tests.rs"]
mod disk_tests;
