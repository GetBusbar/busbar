// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND ON THE ONE DISPATCHER (`BUSBAR-1.6.0.md` THE DESIGN §11.4 and §11.7; the
//! SWITCH-OVER card, hook root axis): [`HookRows`] holds every `kind: hook` plugin the composition
//! root admitted — a compiled-in door and a dropped-in library whose signed manifest states its
//! Statement — as the boot stages' [`Candidate`]s, and binds each through the one loader path
//! ([`load_linked`] / [`load_dropped_bytes`]). [`HookInstance`], one opened instance, is called
//! through the hook kind's table (`abi::hook`) and nothing else, whichever door it came in by. The
//! two implement the contract's [`HookAxis`] and [`HookCalls`], so the kernel probes, opens and
//! calls hooks naming neither this crate nor the root.
//!
//! * Every call is SUBMITTED on a ticket and awaited: it runs on the dispatcher's workers, never on
//!   the caller's, and is bounded by the call's `budget` (the hook's `timeout_ms`), which is its
//!   deadline on the dispatcher. A `decide`/`transform` answer that is SHORT is re-submitted once
//!   on the same ticket over the frame's regrown buffers (the short-buffer rule).
//! * QUARANTINE (THE DESIGN §11.11, R2): an instance the watchdog faulted (a crossing that never
//!   returned) is never called again. The next call waits for the trial window — 1 s after the
//!   fault, doubling to 30 s on each failed trial — within its own budget and never beyond it, then
//!   binds and opens a FRESH instance through the same door and makes one trial call on it.
//! * A plugin's leased answer (`status`, `describe`) is copied, then its lease released.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use busbar_contract::abi::hook::{
    slot, ConfigureIn, ConfigureOut, DecideOut, DescribeOut, NotifyIn, StatusOut, TransformOut,
};
use busbar_contract::abi::host::hook::{DecideFrame, NotifyFrame};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, InHead, OutHead, Outcome, BLOB_ABSENT, BLOB_JSON,
};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, ReleaseIn, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::conn::DeclaredConns;
use busbar_contract::hook_calls::{Answered, HookAxis, HookCalls, HookFacts, Pending, Probed};

use crate::boot::{Candidate, Origin};
use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::{
    in_head, load_dropped_bytes, load_linked, now_ns, out_head, Bind, Dispatcher, EnvelopeSink,
    Frame, InFrame, Lent, NoSink, OutFrame, Plugin, PluginLogConfig, NO_BLOB,
};
use crate::PluginRegistry;

/// The host's clamp on a hook Statement's `max_inflight`.
const MAX_INFLIGHT_CAP: u32 = 64;
/// The first trial window after a fault.
pub const QUARANTINE_FIRST: Duration = Duration::from_secs(1);
/// The longest trial window: each failed trial doubles the window up to this.
pub const QUARANTINE_MAX: Duration = Duration::from_secs(30);

/// A string the host lends for a call; empty is absent (NULL).
fn lend(s: &str) -> AbiStr {
    AbiStr {
        ptr: if s.is_empty() {
            std::ptr::null()
        } else {
            s.as_ptr()
        },
        len: s.len(),
    }
}

/// JSON bytes the host lends for a call.
fn json(b: &[u8]) -> Blob {
    if b.is_empty() {
        return NO_BLOB;
    }
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

/// A plugin-owned blob's bytes, copied (the dispatcher's checks bounded them).
fn copy_blob(b: Blob) -> Vec<u8> {
    if b.len == 0 || b.ptr.is_null() || b.fmt == BLOB_ABSENT {
        return Vec::new();
    }
    // SAFETY: a checked plugin-owned blob, live under its lease until `release`.
    unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
}

/// A plugin's error text, lossily UTF-8.
fn text(error: Option<Vec<u8>>) -> Option<String> {
    error
        .map(|e| String::from_utf8_lossy(&e).into_owned())
        .filter(|t| !t.is_empty())
}

/// Hand a lease back (ticket-less; a release never pends). `0` is none.
fn release(plugin: &Plugin<Hook>, lease: u64) {
    if lease == 0 {
        return;
    }
    let mut f = Frame::new(
        ReleaseIn {
            head: in_head(),
            lease,
        },
        out_head(),
    );
    let _ = plugin.call(life::RELEASE, &mut f);
}

/// `validate` `settings` (ticket-less; it never pends): `Ok` when READY, else the plugin's words.
///
/// # Errors
/// The plugin's refusal, verbatim.
pub fn validate(plugin: &Plugin<Hook>, settings: &[u8]) -> Result<(), String> {
    let mut f = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json(settings),
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    let c = plugin.call(life::VALIDATE, &mut f);
    match c.outcome {
        Outcome::Ready => Ok(()),
        o => Err(text(c.error).unwrap_or_else(|| format!("{o:?}"))),
    }
}

/// `open` `plugin` over `settings` (ticket-less; it never pends).
///
/// # Errors
/// The plugin's refusal, in 1.5.5's words (`plugin '<name>' open failed: <reason>`).
fn open(plugin: &Plugin<Hook>, settings: &[u8]) -> Result<(), String> {
    let mut f = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: json(settings),
            secrets: std::ptr::null(),
            secrets_len: 0,
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
    if c.outcome == Outcome::Ready {
        Ok(())
    } else {
        Err(c.open_failure(plugin.name()))
    }
}

/// `close` `plugin` (ticket-less).
fn close(plugin: &Plugin<Hook>) {
    let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
    let _ = plugin.call(life::CLOSE, &mut f);
}

/// Binds a FRESH instance of the same plugin through its door (the quarantine's trial).
type Rebind = Box<dyn Fn() -> Result<Plugin<Hook>, String> + Send + Sync>;

/// Where an instance stands.
enum State {
    /// Opened and callable.
    Live(Plugin<Hook>),
    /// Faulted: no call reaches a plugin before `trial_at`; the trial then opens a fresh instance.
    /// `window` is the wait that set `trial_at`; a failed trial doubles it.
    Quarantined { trial_at: Instant, window: Duration },
}

struct Inner {
    name: String,
    dispatcher: Arc<Dispatcher>,
    rebind: Rebind,
    settings: Vec<u8>,
    state: Mutex<State>,
    next_worker: AtomicU32,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The instance to call before `deadline`: the live one, or — once the trial window opens
    /// within `deadline` — a fresh one. `Err` says why there is none.
    async fn live(&self, deadline: Instant) -> Result<Plugin<Hook>, String> {
        loop {
            let wait = {
                let mut state = self.lock();
                match &*state {
                    State::Live(p) if !p.is_faulted() => return Ok(p.clone()),
                    State::Live(p) => {
                        close(p);
                        *state = State::Quarantined {
                            trial_at: Instant::now() + QUARANTINE_FIRST,
                            window: QUARANTINE_FIRST,
                        };
                        continue;
                    }
                    State::Quarantined { trial_at, window } => {
                        let now = Instant::now();
                        if now >= *trial_at {
                            match (self.rebind)().and_then(|p| {
                                open(&p, &self.settings)?;
                                Ok(p)
                            }) {
                                Ok(p) => {
                                    *state = State::Live(p.clone());
                                    return Ok(p);
                                }
                                Err(e) => {
                                    let window = (*window * 2).min(QUARANTINE_MAX);
                                    *state = State::Quarantined {
                                        trial_at: now + window,
                                        window,
                                    };
                                    return Err(format!(
                                        "hook '{}' is quarantined: its trial did not open: {e}",
                                        self.name
                                    ));
                                }
                            }
                        }
                        if *trial_at > deadline {
                            return Err(format!(
                                "hook '{}' is quarantined past the call's budget",
                                self.name
                            ));
                        }
                        *trial_at - now
                    }
                }
            };
            tokio::time::sleep(wait).await;
        }
    }

    /// A trial (or any) call that ended in FAULT: an instance the watchdog faulted goes to
    /// quarantine at once; one that faulted only this answer stays live.
    fn faulted(&self, plugin: &Plugin<Hook>) {
        if !plugin.is_faulted() {
            return;
        }
        let mut state = self.lock();
        let window = match &*state {
            State::Live(_) => QUARANTINE_FIRST,
            State::Quarantined { window, .. } => (*window * 2).min(QUARANTINE_MAX),
        };
        close(plugin);
        *state = State::Quarantined {
            trial_at: Instant::now() + window,
            window,
        };
    }

    /// SUBMIT op `s` with the frame `make` builds (re-built over `regrow` once after a SHORT
    /// answer), lending `lent` to the op, bounded by `budget`. `None` = no answer could be had
    /// (named).
    async fn submit<I, O>(
        &self,
        s: u32,
        budget: Duration,
        lent: Lent,
        make: impl Fn() -> Frame<I, O> + Send,
        mut regrow: impl FnMut(&O) -> Option<Lent> + Send,
    ) -> Result<Submitted<O>, Answered<O>>
    where
        I: InFrame,
        O: OutFrame + Copy,
    {
        let deadline = Instant::now() + budget;
        let plugin = self.live(deadline).await.map_err(Answered::Broken)?;
        let workers = self.dispatcher.workers().max(1);
        let worker = self.next_worker.fetch_add(1, Ordering::Relaxed) % workers;
        let Some(ticket) = self.dispatcher.mint(worker) else {
            return Err(Answered::Broken(format!(
                "hook '{}' could not be called: no ticket",
                self.name
            )));
        };
        let mut guard = Ticketed {
            dispatcher: Arc::clone(&self.dispatcher),
            ticket,
            answered: false,
        };
        let deadline_ns =
            now_ns().saturating_add(u64::try_from(budget.as_nanos()).unwrap_or(u64::MAX));
        let mut lent = lent;
        let mut first = true;
        loop {
            let reply = self.dispatcher.submit_lent(
                &plugin,
                ticket,
                s,
                make(),
                DeadlineClass::Call,
                deadline_ns,
                Arc::clone(&lent),
            );
            let done = reply.await;
            let out = done.frame.as_ref().map(|f| f.out);
            if done.short && first {
                if let Some(grown) = out.as_ref().and_then(&mut regrow) {
                    first = false;
                    lent = grown;
                    continue;
                }
            }
            guard.answered = true;
            return match (done.outcome, out) {
                (Outcome::Ready | Outcome::Failed, _) if done.disposition.is_some() => {
                    Err(Answered::TimedOut)
                }
                (Outcome::Ready | Outcome::Failed, Some(out)) => Ok(Submitted {
                    plugin,
                    outcome: done.outcome,
                    out,
                    error: text(done.error),
                    lease: done.lease,
                    lent,
                }),
                (Outcome::Fault, _) => {
                    self.faulted(&plugin);
                    Err(Answered::Broken(format!(
                        "hook '{}' broke the hook kind's contract (FAULT)",
                        self.name
                    )))
                }
                (o, _) => Err(Answered::Broken(format!(
                    "hook '{}' answered {o:?}{}",
                    self.name,
                    text(done.error).map_or_else(String::new, |t| format!(": {t}"))
                ))),
            };
        }
    }
}

/// What one submitted op answered (READY or FAILED, with its `out`).
struct Submitted<O> {
    plugin: Plugin<Hook>,
    outcome: Outcome,
    out: O,
    error: Option<String>,
    lease: u64,
    /// The memory the answering call was lent (the frame whose host buffers it wrote).
    lent: Lent,
}

/// A submitted op's ticket: recycled when the answer is read, and handed to the client-drop path
/// first when the caller stopped waiting before it (the lent memory stays with the op).
struct Ticketed {
    dispatcher: Arc<Dispatcher>,
    ticket: Ticket,
    answered: bool,
}

impl Drop for Ticketed {
    fn drop(&mut self) {
        if !self.answered {
            self.dispatcher.drop_client(self.ticket);
        }
        self.dispatcher.recycle(self.ticket);
    }
}

/// ONE OPENED HOOK INSTANCE, called through the hook kind's table on the one dispatcher. Cheap to
/// clone; every clone is the same instance. Closed when its last clone drops.
#[derive(Clone)]
pub struct HookInstance {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for HookInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookInstance")
            .field("name", &self.inner.name)
            .finish_non_exhaustive()
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let State::Live(p) = &*self.lock() {
            close(p);
        }
    }
}

impl HookInstance {
    /// `open` `plugin` over `settings` (JSON bytes) on `dispatcher`; `rebind` binds a fresh
    /// instance of the same plugin through its door when a quarantine's trial window opens.
    ///
    /// # Errors
    /// The plugin's refusal, in 1.5.5's words.
    pub fn open(
        plugin: Plugin<Hook>,
        dispatcher: Arc<Dispatcher>,
        settings: &[u8],
        rebind: impl Fn() -> Result<Plugin<Hook>, String> + Send + Sync + 'static,
    ) -> Result<Self, String> {
        open(&plugin, settings)?;
        Ok(Self {
            inner: Arc::new(Inner {
                name: plugin.name().to_string(),
                dispatcher,
                rebind: Box::new(rebind),
                settings: settings.to_vec(),
                state: Mutex::new(State::Live(plugin)),
                next_worker: AtomicU32::new(0),
            }),
        })
    }

    /// Whether the instance is quarantined now (no call reaches a plugin until its trial).
    #[must_use]
    pub fn quarantined(&self) -> bool {
        match &*self.inner.lock() {
            State::Live(p) => p.is_faulted(),
            State::Quarantined { .. } => true,
        }
    }

    /// `decide` or `transform` over `frame`.
    fn verdict<O>(&self, s: u32, frame: Arc<DecideFrame>, budget: Duration) -> Pending<Answered<O>>
    where
        O: OutFrame + Copy + 'static,
    {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let current = Arc::new(Mutex::new(Arc::clone(&frame)));
            let make = {
                let current = Arc::clone(&current);
                move || {
                    let f = current.lock().unwrap_or_else(|p| p.into_inner()).input();
                    Frame::new(f, blank_out::<O>())
                }
            };
            let regrow = {
                let current = Arc::clone(&current);
                move |out: &O| {
                    let mut c = current.lock().unwrap_or_else(|p| p.into_inner());
                    let grown = regrown(&c, s, out)?;
                    *c = Arc::clone(&grown);
                    Some(grown as Lent)
                }
            };
            match inner.submit(s, budget, frame as Lent, make, regrow).await {
                Ok(done) => {
                    release(&done.plugin, done.lease);
                    let frame = current.lock().unwrap_or_else(|p| p.into_inner()).clone();
                    drop(done.lent);
                    Answered::Answer {
                        outcome: done.outcome,
                        out: done.out,
                        error: done.error,
                        frame,
                    }
                }
                Err(a) => a,
            }
        })
    }

    /// A ticketed op whose answer is a leased blob (`status`, `describe`), copied out.
    fn leased<O>(&self, s: u32, budget: Duration, blob: fn(&O) -> Blob) -> Pending<Option<Vec<u8>>>
    where
        O: OutFrame + Copy + 'static,
    {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let done = inner
                .submit(
                    s,
                    budget,
                    Arc::new(()) as Lent,
                    || Frame::new(in_head(), blank_out::<O>()),
                    |_: &O| None,
                )
                .await
                .ok()?;
            if done.outcome != Outcome::Ready {
                release(&done.plugin, done.lease);
                return None;
            }
            let bytes = copy_blob(blob(&done.out));
            release(&done.plugin, done.lease);
            Some(bytes)
        })
    }
}

/// The regrown frame for the one short re-call of `s` (`decide` or `transform`).
fn regrown<O: 'static>(frame: &DecideFrame, s: u32, out: &O) -> Option<Arc<DecideFrame>> {
    let out: &dyn std::any::Any = out;
    match s {
        slot::DECIDE => out
            .downcast_ref::<DecideOut>()
            .map(|o| frame.regrown_decide(o)),
        slot::TRANSFORM => out
            .downcast_ref::<TransformOut>()
            .map(|o| frame.regrown_transform(o)),
        _ => None,
    }
}

/// An `out` of `O`, every field zero but its head (the host's FAULT pre-fill; the dispatcher
/// writes the head again before every crossing).
fn blank_out<O: OutFrame>() -> O {
    // SAFETY: every hook `out` is plain integers, raw pointers and blobs, for which the all-zero
    // pattern is valid (NULL pointers, absent blobs).
    let mut out: O = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    // SAFETY: `O: OutFrame` leads with an `OutHead`.
    unsafe {
        std::ptr::addr_of_mut!(out)
            .cast::<OutHead>()
            .write(out_head());
    }
    out
}

impl HookCalls for HookInstance {
    fn name(&self) -> &str {
        &self.inner.name
    }

    fn decide(&self, frame: Arc<DecideFrame>, budget: Duration) -> Pending<Answered<DecideOut>> {
        self.verdict(slot::DECIDE, frame, budget)
    }

    fn transform(
        &self,
        frame: Arc<DecideFrame>,
        budget: Duration,
    ) -> Pending<Answered<TransformOut>> {
        self.verdict(slot::TRANSFORM, frame, budget)
    }

    fn notify(&self, frame: Arc<NotifyFrame>, budget: Duration) -> Pending<()> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let held: Held<NotifyIn> = Held(frame.input());
            let _ = inner
                .submit(
                    slot::NOTIFY,
                    budget,
                    frame as Lent,
                    move || Frame::new(held.0, out_head()),
                    |_: &OutHead| None,
                )
                .await;
        })
    }

    fn configure(
        &self,
        name: &str,
        settings: &str,
        version: u64,
        budget: Duration,
    ) -> Pending<Result<(), String>> {
        let inner = Arc::clone(&self.inner);
        let owned = Arc::new((name.to_string(), settings.as_bytes().to_vec()));
        Box::pin(async move {
            let lent = Arc::clone(&owned);
            let make = move || {
                Frame::new(
                    ConfigureIn {
                        head: in_head(),
                        version,
                        settings: json(&lent.1),
                        name: lend(&lent.0),
                    },
                    blank_out::<ConfigureOut>(),
                )
            };
            let hook = inner.name.clone();
            match inner
                .submit(
                    slot::CONFIGURE,
                    budget,
                    owned as Lent,
                    make,
                    |_: &ConfigureOut| None,
                )
                .await
            {
                Ok(done) if done.outcome == Outcome::Ready && done.out.acked_version == version => {
                    release(&done.plugin, done.lease);
                    Ok(())
                }
                Ok(done) => {
                    release(&done.plugin, done.lease);
                    Err(done.error.unwrap_or_else(|| {
                        format!("hook '{hook}' did not acknowledge settings version {version}")
                    }))
                }
                Err(Answered::TimedOut) => Err(format!(
                    "hook '{hook}' did not acknowledge settings version {version} within its budget"
                )),
                Err(Answered::Broken(why)) => Err(why),
                Err(Answered::Answer { .. }) => Err(format!("hook '{hook}' answered out of turn")),
            }
        })
    }

    fn status(&self, budget: Duration) -> Pending<Option<Vec<u8>>> {
        self.leased::<StatusOut>(slot::STATUS, budget, |o| o.status)
    }

    fn describe(&self, budget: Duration) -> Pending<Option<Vec<u8>>> {
        self.leased::<DescribeOut>(slot::DESCRIBE, budget, |o| o.describe)
    }
}

/// A host-built `in` that points at memory the calling future owns (or holds lent), carried
/// across its await.
struct Held<T>(T);
// SAFETY: the pointers inside point at data the same future owns or lends to the op for its whole
// life; one thread touches the future at a time.
unsafe impl<T> Send for Held<T> {}

// ── THE HOOK ROWS: the axis the composition root installs ─────────────────────────────────────

/// THE PROCESS'S HOOK PLUGINS, by Statement name and alias: the compiled-in doors and the
/// dropped-in libraries whose signed manifests state a Statement, each bound on open through the
/// one loader path and called through the one dispatcher. A linked row answers ahead of a
/// dropped-in plugin spelling the same word (the boot stages' selection rule).
pub struct HookRows {
    candidates: Vec<Candidate>,
    /// The dropped-in rows signed by the release key (a linked row is first-party by construction).
    first_party: Vec<String>,
    dispatcher: Arc<Dispatcher>,
    /// `plugins.logs`: each OPENED instance's own log sink; `None` = its records are discarded.
    logs: Option<PluginLogConfig>,
    /// The host's one connection table: an OPENED instance's needs are declared on it.
    conns: Option<Arc<dyn DeclaredConns>>,
}

impl std::fmt::Debug for HookRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookRows")
            .field(
                "candidates",
                &self.candidates.iter().map(|c| &c.name).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl HookRows {
    /// The compiled-in hook doors `linked`, then every loadable dropped-in `kind: hook` plugin of
    /// `registry` whose signed manifest states a Statement, bound on `dispatcher`. A dropped-in
    /// hook that states none speaks the 1.5.5 JSON contract and is not a row here.
    ///
    /// # Errors
    /// The first row that will not state itself, named.
    pub fn new(
        linked: &[DoorFn],
        registry: Option<&PluginRegistry>,
        dispatcher: Arc<Dispatcher>,
    ) -> Result<Self, String> {
        let mut candidates = Vec::new();
        let mut first_party = Vec::new();
        for door in linked {
            let c = Candidate::linked(*door)?;
            if c.kind != KindCode::Hook {
                return Err(format!(
                    "the linked hook door '{}' states another kind",
                    c.name
                ));
            }
            candidates.push(c);
        }
        let hook = busbar_contract::abi::cold::kind::HOOK;
        for p in registry
            .map_or(&[][..], PluginRegistry::loadable)
            .iter()
            .filter(|p| p.manifest.kind == hook)
        {
            let named = |e: String| format!("plugin '{}': {e}", p.manifest.name);
            let Some(stated) = p.manifest.stated_rendering().map_err(named)? else {
                continue;
            };
            let c = Candidate::from_rendering(
                stated,
                Some(&p.manifest.alias),
                Origin::Dropped {
                    file: p.file.clone(),
                    bytes: Arc::new(p.lib_bytes.clone()),
                },
            )
            .map_err(named)?;
            if p.first_party() {
                first_party.push(c.name.clone());
            }
            candidates.push(c);
        }
        let mut rows = Self::of(candidates, dispatcher);
        rows.first_party = first_party;
        Ok(rows)
    }

    /// The rows `candidates` state (each a `kind: hook` candidate, a linked one ahead of a
    /// dropped-in one spelling the same word), bound on `dispatcher`. Only a linked row is
    /// first-party here; [`Self::new`] adds the dropped-in rows the release key signed.
    #[must_use]
    pub fn of(candidates: Vec<Candidate>, dispatcher: Arc<Dispatcher>) -> Self {
        Self {
            candidates,
            first_party: Vec::new(),
            dispatcher,
            logs: None,
            conns: None,
        }
    }

    /// Each opened instance logs to its own sink under `logs`.
    #[must_use]
    pub fn with_logs(mut self, logs: PluginLogConfig) -> Self {
        self.logs = Some(logs);
        self
    }

    /// Each opened instance declares its needs on `conns`.
    #[must_use]
    pub fn with_conns(mut self, conns: Arc<dyn DeclaredConns>) -> Self {
        self.conns = Some(conns);
        self
    }

    /// The row config names `module` by: its Statement name or an alias, a linked row first.
    fn find(&self, module: &str) -> Option<&Candidate> {
        self.candidates
            .iter()
            .find(|c| c.name == module || c.aliases.iter().any(|a| a == module))
    }

    /// Bind `c` under `label`: an instance only probed binds with no log sink and no connection
    /// table; one opened to serve binds with both.
    fn bind(
        c: &Candidate,
        dispatcher: &Dispatcher,
        label: &str,
        sink: Arc<dyn EnvelopeSink>,
        conns: Option<Arc<dyn DeclaredConns>>,
    ) -> Result<Plugin<Hook>, String> {
        let bind = Bind {
            instance: Arc::from(label),
            max_inflight_cap: MAX_INFLIGHT_CAP,
            sink,
            dispatcher: dispatcher.adopter(),
            conns,
        };
        match &c.origin {
            Origin::Linked(row) => load_linked::<Hook>(row, bind),
            Origin::Dropped { file, bytes } => {
                load_dropped_bytes::<Hook>(bytes, file, &c.stated, bind)
            }
        }
        .map_err(|e| format!("hook plugin '{}': {e}", c.name))
    }
}

impl HookAxis for HookRows {
    fn probe(&self, module: &str, instance: &str, settings: &serde_json::Value) -> Option<Probed> {
        let c = self.find(module)?;
        let Ok(p) = Self::bind(c, &self.dispatcher, instance, Arc::new(NoSink), None) else {
            // It will not load here: its open refuses the boot naming the instance.
            return Some((None, Vec::new()));
        };
        let facts = p.context::<HookFacts>().cloned();
        let problems = match validate(&p, settings.to_string().as_bytes()) {
            Ok(()) => Vec::new(),
            Err(words) => words.lines().map(str::to_string).collect(),
        };
        Some((facts, problems))
    }

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
        _budget: Duration,
    ) -> Result<Arc<dyn HookCalls>, String> {
        let c = self
            .find(module)
            .ok_or_else(|| format!("no `kind: hook` plugin answers to '{module}'"))?
            .clone();
        let sink = |label: &str| -> Result<Arc<dyn EnvelopeSink>, String> {
            Ok(match &self.logs {
                Some(logs) => Arc::new(logs.sink(label, KindCode::Hook, Arc::new(NoSink))?),
                None => Arc::new(NoSink),
            })
        };
        let plugin = Self::bind(
            &c,
            &self.dispatcher,
            label,
            sink(label)?,
            self.conns.clone(),
        )?;
        let rebind = {
            let (dispatcher, conns, label) = (
                Arc::clone(&self.dispatcher),
                self.conns.clone(),
                label.to_string(),
            );
            let sink = sink(label.as_str())?;
            move || Self::bind(&c, &dispatcher, &label, Arc::clone(&sink), conns.clone())
        };
        let text = settings.to_string();
        let opened = HookInstance::open(
            plugin,
            Arc::clone(&self.dispatcher),
            text.as_bytes(),
            rebind,
        )?;
        Ok(Arc::new(opened))
    }

    fn linked(&self, module: &str) -> bool {
        self.find(module)
            .is_some_and(|c| matches!(c.origin, Origin::Linked(_)))
    }

    fn first_party(&self, module: &str) -> bool {
        self.find(module).is_some_and(|c| {
            matches!(c.origin, Origin::Linked(_)) || self.first_party.iter().any(|n| *n == c.name)
        })
    }
}

#[cfg(test)]
#[path = "tests/hook_door_tests.rs"]
mod tests;
