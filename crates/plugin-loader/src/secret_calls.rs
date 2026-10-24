// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S CALLS over the one dispatcher (THE DESIGN, "Plugins" and the plugin ABI; TODO step 28): the
//! contract's [`SecretAxis`] and [`SecretCalls`], implemented here over [`Plugin`]`<`[`Secret`]`>`.
//! [`SecretRows`] holds every secret plugin the composition root admitted — a compiled-in row (its
//! linked door) and a dropped-in one (its verified library, discovered off its signed manifest) —
//! as the [`Candidate`]s the boot stages read, and loads each through the one loader path
//! ([`load_linked`] / [`load_dropped_bytes`]) only when a reference first names it. Nothing here
//! reads which door a plugin came in by once it is loaded.
//!
//! `open` is a ticket-less crossing (it may not pend); `resolve` is submitted on a ticket and the
//! calling thread waits for its answer, which may PEND (the dispatcher's worker drives it). The
//! material is copied out of the plugin's lease into a [`SecretValue`] and the lease is released before
//! `resolve` returns, so no plugin memory outlives the call. An instance is closed when its last
//! handle drops.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use crate::open_once::OpenOnce;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{
    Blob, DeadlineClass, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, ReleaseIn};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::secret::{
    slot, ResolveIn, ResolveOut, ERROR_KIND_DENIED, ERROR_KIND_INTERNAL, ERROR_KIND_UNAVAILABLE,
};
use busbar_contract::config_time::{ConfigScope, RESOLVE_OFF_CONFIG_TIME};
use busbar_contract::conn::DeclaredConns;
use busbar_contract::redacted::Secret as SecretValue;
use busbar_contract::secret::{SecretAxis, SecretCalls, SecretRefused};
use busbar_contract::secret_ref::SecretRef;

use crate::boot::{Candidate, Origin};
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::{
    in_head, load_dropped_bytes, load_linked, now_ns, out_head, Bind, ConnTable, Dispatcher,
    EnvelopeSink, Frame, NoSink, Plugin, PluginLogConfig, NO_BLOB,
};

/// How long a `resolve` may pend before the dispatcher cancels it (the Call budget).
const CALL_DEADLINE: Duration = Duration::from_secs(30);

/// The longest the calling thread waits for one answer: past the Call budget, so the dispatcher's
/// own cancel ends a slow op first; this bounds a wait on a dispatcher that stopped.
const WAIT: Duration = Duration::from_secs(40);

/// How many calls one secret instance holds in flight, at most.
const MAX_INFLIGHT_CAP: u32 = 16;

/// The host's hook onto its one bounded disk lane (THE DESIGN §11.11 R4): run a job on the lane
/// thread, or say why it was not taken (the lane is full or not running).
pub type DiskRun = fn(Box<dyn FnOnce() + Send>) -> Result<(), String>;

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

/// ONE OPENED SECRET PLUGIN INSTANCE: its calls through the one dispatcher, or — for a source that
/// declares a disk need — on the host's disk lane at config time only. Closed when its last handle
/// drops (a lane job holds one).
pub struct LoadedSecret {
    opened: Arc<Opened>,
    dispatcher: Arc<Dispatcher>,
    next_worker: AtomicU32,
    disk: Disk,
}

/// The opened instance itself, shared with a lane job running its `resolve`. Closed on drop.
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

/// `bytes` as a blob the host owns for the call (`NO_BLOB` when empty).
fn blob(bytes: &[u8], fmt: u32, flags: u32) -> Blob {
    if bytes.is_empty() {
        return NO_BLOB;
    }
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt,
        flags,
    }
}

fn refused(error_kind: u32, text: String) -> SecretRefused {
    SecretRefused { error_kind, text }
}

/// The text of a refused answer: the plugin's own, else `fallback`.
fn answer_text(error: Option<&[u8]>, fallback: String) -> String {
    error
        .map(|e| String::from_utf8_lossy(e).into_owned())
        .filter(|t| !t.is_empty())
        .unwrap_or(fallback)
}

impl LoadedSecret {
    /// `open` `plugin` over its module `settings` (JSON bytes, empty = none) and the material its
    /// Statement's `secret_refs` resolved to, in order, on `dispatcher`. The material is revealed
    /// under the seal the host lent `dispatcher` (Part 2 #54).
    ///
    /// # Errors
    /// The plugin's refusal, in 1.5.5's words (`plugin '<name>' open failed: <reason>`); material
    /// to hand over on a dispatcher lent no seal (refused, never revealed).
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
        let mut f = Frame::new(
            OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: blob(settings, BLOB_JSON, 0),
                secrets: lent.as_ptr(),
                secrets_len: lent.len(),
                generation: 1,
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                err_len: 0,
            },
        );
        let c = plugin.call(life::OPEN, &mut f);
        if c.outcome != Outcome::Ready {
            return Err(c.open_failure(plugin.name()));
        }
        Ok(Self {
            opened: Arc::new(Opened { plugin }),
            dispatcher,
            next_worker: AtomicU32::new(0),
            disk: Disk::No,
        })
    }

    /// This instance as a source that reads the disk (its `declares.disk`, THE DESIGN §11.11 R4):
    /// its `resolve` runs on the host's disk lane `lane` at config time only, and is refused without
    /// the config-time proof. With no lane wired, every resolve is refused.
    #[must_use]
    pub fn reading_disk(mut self, lane: Option<DiskRun>) -> Self {
        self.disk = lane.map_or(Disk::Unwired, Disk::Lane);
        self
    }

    /// The plugin's Statement name.
    pub fn name(&self) -> &str {
        self.opened.plugin.name()
    }

    /// `resolve` on the host's disk lane: the job runs the plugin's `resolve` on the lane thread
    /// (a ticket-less crossing, which may not pend) and the caller waits for its answer, bounded by
    /// [`WAIT`] whatever the lane does.
    fn resolve_on_lane(
        &self,
        lane: DiskRun,
        settings: &[u8],
    ) -> Result<SecretValue<Vec<u8>>, SecretRefused> {
        let name = self.name().to_string();
        let opened = Arc::clone(&self.opened);
        let owned = settings.to_vec();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        lane(Box::new(move || {
            let _ = tx.send(opened.resolve_here(&owned));
        }))
        .map_err(|e| {
            refused(
                ERROR_KIND_UNAVAILABLE,
                format!("secret module '{name}' could not reach the host's disk lane: {e}"),
            )
        })?;
        rx.recv_timeout(WAIT).unwrap_or_else(|_| {
            Err(refused(
                ERROR_KIND_INTERNAL,
                format!("secret module '{name}' did not answer its resolve on the disk lane"),
            ))
        })
    }
}

impl Opened {
    /// Hand `lease` back (ticket-less; a release never pends).
    fn release(&self, lease: u64) {
        let mut f = Frame::new(
            ReleaseIn {
                head: in_head(),
                lease,
            },
            out_head(),
        );
        let _ = self.plugin.call(life::RELEASE, &mut f);
    }

    /// `resolve` on THIS thread, ticket-less: the disk lane's crossing. The material is copied out
    /// of the plugin's lease and the lease released before this returns.
    fn resolve_here(&self, settings: &[u8]) -> Result<SecretValue<Vec<u8>>, SecretRefused> {
        let name = self.plugin.name();
        let mut f = Frame::new(
            ResolveIn {
                head: in_head(),
                settings: blob(settings, BLOB_JSON, 0),
            },
            ResolveOut {
                head: out_head(),
                secret: NO_BLOB,
                error_kind: 0,
                _reserved: 0,
            },
        );
        let c = self.plugin.call(slot::RESOLVE, &mut f);
        match c.outcome {
            Outcome::Ready => {
                let b = f.out.secret;
                // SAFETY: a READY resolve's `secret` names plugin memory held under the answer's
                // lease until `release` (the secret kind's answer rule, checked by `check_resolve`
                // in the crossing); it is copied here, before the release below.
                let material = if b.ptr.is_null() || b.len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
                };
                let material = SecretValue::new(material);
                if c.lease != 0 {
                    self.release(c.lease);
                }
                Ok(material)
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
        let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
        let _ = self.plugin.call(life::CLOSE, &mut f);
    }
}

impl SecretCalls for LoadedSecret {
    fn resolve(&self, settings: &[u8]) -> Result<SecretValue<Vec<u8>>, SecretRefused> {
        let name = self.name();
        if !matches!(self.disk, Disk::No) {
            // A source that reads the disk answers at config time only (THE DESIGN §11.11 R4).
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
        // The settings ride with the job: a crossing the watchdog answered still owns them until
        // it returns.
        let owned: Arc<Vec<u8>> = Arc::new(settings.to_vec());
        let frame = Frame::new(
            ResolveIn {
                head: in_head(),
                settings: blob(&owned, BLOB_JSON, 0),
            },
            ResolveOut {
                head: out_head(),
                secret: NO_BLOB,
                error_kind: 0,
                _reserved: 0,
            },
        );
        let deadline = now_ns().saturating_add(CALL_DEADLINE.as_nanos() as u64);
        let done = self
            .dispatcher
            .submit_lent(
                plugin,
                ticket,
                slot::RESOLVE,
                frame,
                DeadlineClass::Call,
                deadline,
                owned,
            )
            .wait(WAIT);
        self.dispatcher.recycle(ticket);
        let Some(done) = done else {
            return Err(refused(
                ERROR_KIND_INTERNAL,
                format!("secret module '{name}' did not answer its resolve"),
            ));
        };
        match (done.outcome, done.frame.as_deref()) {
            (Outcome::Ready, Some(f)) => {
                let b = f.out.secret;
                // SAFETY: a READY resolve's `secret` names plugin memory held under the answer's
                // lease until `release` (the secret kind's answer rule, checked by `check_resolve`
                // before this answer was settled); it is copied here, before the release below.
                let material = if b.ptr.is_null() || b.len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
                };
                let material = SecretValue::new(material);
                if done.lease != 0 {
                    self.opened.release(done.lease);
                }
                Ok(material)
            }
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

/// THE PROCESS'S SECRET PLUGINS, by Statement name and alias: the linked rows (fixed at build) and
/// the dropped-in ones (replaced at each admission), each loaded on first use through the one
/// loader and called through the one dispatcher. Two different plugins answering one word are
/// refused when the dropped-in set is admitted ([`SecretRows::admit_dropped`], ARCHITECT Q-P4-12);
/// neither door outranks the other. The composition root builds it and
/// installs it as the kernel's [`SecretAxis`].
pub struct SecretRows {
    /// The process dispatcher, asked for at first use: a plugin is opened on it, never before.
    dispatcher: fn() -> Arc<Dispatcher>,
    /// The host's one connection table, asked for at each load: a plugin that declares a need (a
    /// dropped-in vault's http exchange) is declared on it and lent its connector.
    conns: fn() -> Option<Arc<dyn DeclaredConns>>,
    /// `plugins.logs`, asked for at each load: every opened instance logs to its own
    /// `<dir>/<label>.log`. `None` = no log configuration is wired (records are discarded).
    logs: Option<fn() -> PluginLogConfig>,
    linked: Vec<Candidate>,
    dropped: RwLock<Vec<Candidate>>,
    /// Each linked module's shared instance, opened outside the map's lock ([`OpenOnce`]).
    shared: OpenOnce<String, LoadedSecret>,
    /// The host's one disk lane, where a source that declares a disk need resolves at config time.
    /// `None` = no lane is wired (such a source refuses every resolve).
    disk_run: Option<DiskRun>,
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

/// Whether config names `c` by `word` (its name or an alias).
fn answers(c: &Candidate, word: &str) -> bool {
    c.name == word || c.aliases.iter().any(|a| a == word)
}

impl SecretRows {
    /// No rows yet; every instance opens on the dispatcher `dispatcher` answers, asked for at the
    /// first open (so the rows can be built before the process dispatcher is), its needs declared on
    /// the connection table `conns` answers.
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
        }
    }

    /// A source that declares a disk need resolves on the host's one disk lane `run`, at config
    /// time only (THE DESIGN §11.11 R4, as the OWNER amended it 2026-10-13).
    #[must_use]
    pub fn with_disk_lane(mut self, run: DiskRun) -> Self {
        self.disk_run = Some(run);
        self
    }

    /// The LINKED row `door` states, its `declares.json` `json` read as a dropped-in copy's signed
    /// `declares` is: its disk need.
    ///
    /// # Errors
    /// The door does not state itself, no linked row is that door's plugin, or `json` is not a
    /// `declares` section.
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

    /// The LINKED row `door` states, its `declares` read off its own Statement
    /// ([`crate::sign::Declares::stated_json_of_door`]), as a dropped-in copy's is read off its
    /// signed one: its disk need. A door whose Statement states none declares none.
    ///
    /// # Errors
    /// As [`SecretRows::declare_linked`].
    pub fn declare_linked_stated(&mut self, door: DoorFn) -> Result<&mut Self, String> {
        match crate::sign::Declares::stated_json_of_door(door)? {
            Some(json) => self.declare_linked(door, &json),
            None => Ok(self),
        }
    }

    /// `opened` as `c` declares it: on the disk lane when its source reads the disk.
    fn placed(&self, c: &Candidate, opened: LoadedSecret) -> LoadedSecret {
        if c.disk {
            opened.reading_disk(self.disk_run)
        } else {
            opened
        }
    }

    /// Every opened instance logs to its own file under the `plugins.logs` configuration `logs`
    /// answers (THE DESIGN §11.2 Plugin logging: no logs for plugins is not an option).
    #[must_use]
    pub fn with_logs(mut self, logs: fn() -> PluginLogConfig) -> Self {
        self.logs = Some(logs);
        self
    }

    /// The instance label of a secret instance opened for the configured `module` word (the key of
    /// its `secrets:` entry), as the export kind labels its own (`export.<name>`).
    fn label(module: &str) -> String {
        format!("secrets.{module}")
    }

    /// Add a COMPILED-IN secret plugin by its door: its Statement is rendered and read here (the
    /// door's head and Statement checks); nothing is loaded or opened.
    ///
    /// # Errors
    /// The door's refusal, or a door of another kind.
    pub fn link(&mut self, door: DoorFn) -> Result<&mut Self, String> {
        let c = Candidate::linked(door)?;
        if c.kind != KindCode::Secret {
            return Err(format!(
                "`{}` is a {:?} door, not a secret one",
                c.name, c.kind
            ));
        }
        self.linked.push(c);
        // The sugars the linked rows declare: a word or role two of them claim refuses the link.
        if let Err(e) = crate::boot::sugars_of(&self.linked) {
            self.linked.pop();
            return Err(e);
        }
        Ok(self)
    }

    /// Each LINKED row answering also to the former names `former_of` gives for any of its words
    /// (its name or an alias), as a dropped-in copy states them in its signed manifest (compiled in
    /// = dropped in).
    ///
    /// # Errors
    /// A linked row that would then claim a word another linked plugin answers to, naming both.
    pub fn with_former_names(
        &mut self,
        former_of: impl Fn(&str) -> Vec<String>,
    ) -> Result<&mut Self, String> {
        for c in &mut self.linked {
            let words: Vec<String> = std::iter::once(c.name.clone())
                .chain(c.aliases.iter().cloned())
                .flat_map(|w| former_of(&w))
                .collect();
            *c = c.clone().answering(words);
        }
        crate::boot::one_owner(&self.linked)?;
        Ok(self)
    }

    /// [`Self::set_dropped`], refused when a dropped-in secret plugin and another plugin (linked or
    /// dropped in) answer one word but are different plugins ([`crate::boot::one_owner`]).
    ///
    /// # Errors
    /// The contested word and the two plugins that claim it; the last set stays.
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

    /// The secret-kind candidates among `candidates`, judged as [`Self::admit_dropped`] judges
    /// them and NOT put on the rows: what a build that commits nothing (a dry run) refuses.
    ///
    /// # Errors
    /// The contested word and the two plugins that claim it, or two sugars that collide.
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

    /// The DROPPED-IN secret plugins: every secret-kind candidate among `candidates` (the registry's
    /// discovered rows), replacing the last set.
    pub fn set_dropped(&self, candidates: impl IntoIterator<Item = Candidate>) {
        let secrets = candidates
            .into_iter()
            .filter(|c| c.kind == KindCode::Secret)
            .collect();
        *self.dropped.write().unwrap_or_else(PoisonError::into_inner) = secrets;
    }

    /// The candidate `module` names, linked first; `None` when no row answers it.
    fn find(&self, module: &str) -> Option<Candidate> {
        self.linked
            .iter()
            .find(|c| answers(c, module))
            .cloned()
            .or_else(|| {
                self.dropped
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .iter()
                    .find(|c| answers(c, module))
                    .cloned()
            })
    }

    /// Load `c` through the one loader, bound under the configured instance `label`, its log
    /// records and diagnostics going to that instance's own file.
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
            // Opened to resolve: the host's table, or a door that declares no need.
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

    /// The settings keys `c`'s Statement names as secret references.
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
        // Every row was admitted with its sugars declared ([`Self::link`],
        // [`Self::admit_dropped`]); a set that no longer declares answers no sugar (fail-closed).
        crate::boot::sugars_of(&all).unwrap_or_default()
    }

    fn answers(&self, module: &str) -> bool {
        self.find(module).is_some()
    }

    fn linked(&self, module: &str) -> bool {
        self.linked.iter().any(|c| answers(c, module))
    }

    fn shared(&self, module: &str) -> Result<Arc<dyn SecretCalls>, String> {
        let c = self
            .linked
            .iter()
            .find(|c| answers(c, module))
            .ok_or_else(|| format!("no linked secret module answers to '{module}'"))?;
        // Bound and opened with the map's lock let go (THE DESIGN §11.13 M1).
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
        resolve: &dyn Fn(&SecretRef) -> Result<Vec<u8>, String>,
    ) -> Result<Arc<dyn SecretCalls>, String> {
        let c = self
            .find(module)
            .ok_or_else(|| format!("no secret module answers to '{module}'"))?;
        let mut secrets = Vec::new();
        for key in Self::secret_refs(&c)? {
            let material = match settings.get(&key) {
                None => Vec::new(),
                Some(v) => {
                    // The decoder's own text is withheld: the value may be the secret itself.
                    let r = serde_json::from_value::<SecretRef>(v.clone()).map_err(
                        crate::boot::not_a_reference(format!("secrets.{module}.settings.{key}")),
                    )?;
                    resolve(&r).map_err(|e| format!("secrets.{module}.settings.{key}: {e}"))?
                }
            };
            secrets.push(SecretValue::new(material));
        }
        let bytes = if settings.is_null() {
            Vec::new()
        } else {
            settings.to_string().into_bytes()
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
