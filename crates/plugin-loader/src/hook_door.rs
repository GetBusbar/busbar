// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use busbar_contract::abi::hook::{
    slot, ConfigureIn, ConfigureOut, DecideOut, DescribeOut, NotifyIn, ServeIn, ServeOut,
    StatusOut, TransformOut, VERB_PREFER,
};
use busbar_contract::abi::host::hook::{DecideFrame, NotifyFrame};
use busbar_contract::abi::mechanism::call::{Blob, DeadlineClass, OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::{DoorFn, MARK_WORD_HOOK};
use busbar_contract::abi::mechanism::endpoint::{EndpointRequest, EndpointResponse};
use busbar_contract::abi::mechanism::lifecycle::slot as life;
use busbar_contract::abi::mechanism::route::Route;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::sdk::hook::{configure_checkpoint, ConfigureCheckpoint};
use busbar_contract::conn::DeclaredConns;
use busbar_contract::hook_calls::{Answered, HookAxis, HookCalls, Pending, Probed};

use crate::boot::{Candidate, Origin};
use crate::dispatch::call::Ticketed;
use crate::dispatch::kinds::hook::{Hook, HookContext};
use crate::dispatch::lifecycle::{
    blob, close, copy_blob, lend_or_null, open_frame, release, text, validate_json, AnswerLease,
};
use crate::dispatch::{
    in_head, load_dropped_bytes, load_linked, now_ns, out_head, Bind, ConnTable, Dispatcher,
    EnvelopeSink, Frame, InFrame, Lent, NoSink, OutFrame, Plugin, PluginLogConfig,
};
use crate::PluginRegistry;

pub const JSON_HOOK_REFUSED: &str = "it speaks the 1.5.5 JSON hook contract, which this host does not load — rebuild the plugin against the 1.6.0 SDK";

const MAX_INFLIGHT_CAP: u32 = 64;

pub const QUARANTINE_FIRST: Duration = Duration::from_secs(1);

pub const QUARANTINE_MAX: Duration = Duration::from_secs(30);

const TRIAL_POLL: Duration = Duration::from_millis(5);

const SLOT_WAIT_FIRST: Duration = Duration::from_millis(1);

const SLOT_WAIT_MAX: Duration = Duration::from_millis(16);

fn json(b: &[u8]) -> Blob {
    blob(b, BLOB_JSON, 0)
}

pub fn validate(plugin: &Plugin<Hook>, settings: &[u8]) -> Result<(), String> {
    validate_json(plugin, settings)
}

fn open(plugin: &Plugin<Hook>, settings: &[u8]) -> Result<(), String> {
    let mut f = open_frame(json(settings));
    let c = plugin.call(life::OPEN, &mut f);
    let _lease = AnswerLease::new(plugin, c.lease);
    if c.outcome == Outcome::Ready {
        Ok(())
    } else {
        Err(c.open_failure(plugin.name()))
    }
}

type Rebind = Box<dyn Fn() -> Result<Plugin<Hook>, String> + Send + Sync>;

enum State {
    Live {
        plugin: Arc<Plugin<Hook>>,
        // Opening a trial alone does not show that its serving slots recovered.
        next_fault_window: Duration,
    },

    Quarantined {
        trial_at: Instant,
        window: Duration,
    },

    Trialing,
}

type Pushed = Arc<(String, zeroize::Zeroizing<Vec<u8>>, u64)>;

struct Configured {
    name: String,

    checkpoint: Option<ConfigureCheckpoint>,
}

struct Configuration {
    owner: Weak<Plugin<Hook>>,

    kept: Option<Arc<Configured>>,

    pending: usize,

    uncertain: bool,
}

struct ConfigureAttempt {
    inner: Arc<Inner>,
    target: Option<Weak<Plugin<Hook>>>,
}

impl ConfigureAttempt {
    fn target(&mut self, plugin: &Arc<Plugin<Hook>>) -> Result<(), String> {
        let target = Arc::downgrade(plugin);
        if self.target.as_ref().is_some_and(|old| old.ptr_eq(&target)) {
            return Ok(());
        }
        self.finish(false);
        let mut configured = self
            .inner
            .configured
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !configured.owner.ptr_eq(&target) {
            return Err("hook configuration targeted a retired instance".into());
        }
        configured.pending = configured
            .pending
            .checked_add(1)
            .ok_or("too many outstanding hook configurations")?;
        self.target = Some(target);
        Ok(())
    }

    fn finish(&mut self, known: bool) {
        let Some(target) = self.target.take() else {
            return;
        };
        let mut configured = self
            .inner
            .configured
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if configured.owner.ptr_eq(&target) {
            configured.pending -= 1;
            configured.uncertain |= !known;
        }
    }
}

impl Drop for ConfigureAttempt {
    fn drop(&mut self) {
        self.finish(false);
    }
}

fn checkpoint(out: &ConfigureOut) -> Result<Option<ConfigureCheckpoint>, String> {
    use busbar_contract::abi::mechanism::call::{BLOB_OCTETS, BLOB_SECRET};
    let ext = out.head.extensions;
    if ext.len == 0 {
        return Ok(None);
    }
    if ext.len > configure_checkpoint::MAX_BYTES || ext.ptr.is_null() || ext.fmt != BLOB_OCTETS {
        return Err("invalid hook configuration checkpoint reply".into());
    }
    // SAFETY: the checked configure answer remains live under its plugin lease until release.
    let bytes = unsafe { std::slice::from_raw_parts(ext.ptr, ext.len) };
    let checkpoint = ConfigureCheckpoint::decode(bytes).map_err(str::to_owned)?;
    if checkpoint.is_some() && (out.head.lease == 0 || ext.flags & BLOB_SECRET == 0) {
        return Err("hook configuration checkpoint has no secret lease".into());
    }
    Ok(checkpoint)
}

fn reconfigure(plugin: &Plugin<Hook>, pushed: &Configured) -> Result<ConfigureCheckpoint, String> {
    let saved = pushed
        .checkpoint
        .as_ref()
        .ok_or("hook acknowledged settings without a recovery checkpoint")?;
    let version = saved.settings_version;
    let mut f = Frame::new(
        ConfigureIn {
            head: in_head(),
            version,
            settings: json(saved.settings()),
            name: lend_or_null(&pushed.name),
        },
        blank_out::<ConfigureOut>(),
    );
    let c = plugin.call(slot::CONFIGURE, &mut f);
    let checkpoint = if c.outcome == Outcome::Ready && f.out.acked_version == version {
        checkpoint(&f.out)
    } else {
        Err(c.error.map_or_else(
            || format!("it did not acknowledge settings version {version} again"),
            |e| String::from_utf8_lossy(&e).into_owned(),
        ))
    };
    release(plugin, c.lease);
    let restored = checkpoint?.ok_or("hook did not checkpoint its restored configuration")?;
    if restored.settings_version != version || restored.settings() != saved.settings() {
        return Err("hook did not restore its complete configuration checkpoint".into());
    }
    Ok(restored)
}

struct Inner {
    name: String,
    routes: Vec<Route>,
    dispatcher: Arc<Dispatcher>,
    rebind: Rebind,

    // settings-leak-lint: allow — NON-PROJECTION engine type: the instance's own settings bytes,
    settings: zeroize::Zeroizing<Vec<u8>>,

    configured: Mutex<Configuration>,
    state: Mutex<State>,
    next_worker: AtomicU32,

    orders: bool,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    async fn live(self: &Arc<Self>, deadline: Instant) -> Result<Arc<Plugin<Hook>>, String> {
        loop {
            let (wait, retired, trial) = {
                let mut state = self.lock();
                let now = Instant::now();
                match &*state {
                    State::Live { plugin, .. } if !plugin.is_faulted() => {
                        return Ok(Arc::clone(plugin));
                    }
                    State::Live {
                        next_fault_window, ..
                    } => {
                        let window = *next_fault_window;
                        let State::Live { plugin, .. } = std::mem::replace(
                            &mut *state,
                            State::Quarantined {
                                trial_at: now + window,
                                window,
                            },
                        ) else {
                            unreachable!("matched live")
                        };
                        (Duration::ZERO, Some(plugin), None)
                    }
                    State::Quarantined { trial_at, window } if now >= *trial_at => {
                        let window = *window;
                        *state = State::Trialing;
                        (Duration::ZERO, None, Some(window))
                    }
                    State::Quarantined { trial_at, .. } => {
                        if *trial_at > deadline {
                            return Err(format!(
                                "hook '{}' is quarantined past the call's budget",
                                self.name
                            ));
                        }
                        (*trial_at - now, None, None)
                    }
                    State::Trialing => {
                        if now >= deadline {
                            return Err(format!(
                                "hook '{}' is quarantined past the call's budget",
                                self.name
                            ));
                        }
                        ((deadline - now).min(TRIAL_POLL), None, None)
                    }
                }
            };

            if let Some(p) = retired {
                close(&p);
                continue;
            }
            if let Some(window) = trial {
                let inner = Arc::clone(self);
                let trial = tokio::task::spawn_blocking(move || {
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        inner.trial(window)
                    })) {
                        Ok(answer) => answer,
                        Err(_) => {
                            let mut state = inner.lock();
                            if matches!(*state, State::Trialing) {
                                *state = State::Quarantined {
                                    trial_at: Instant::now() + window,
                                    window,
                                };
                            }
                            Err("hook recovery worker panicked".to_owned())
                        }
                    }
                });
                return match tokio::time::timeout(
                    deadline.saturating_duration_since(Instant::now()),
                    trial,
                )
                .await
                {
                    Ok(Ok(answer)) => answer,
                    Ok(Err(_)) => {
                        *self.lock() = State::Quarantined {
                            trial_at: Instant::now() + window,
                            window,
                        };
                        Err(format!("hook '{}' recovery worker failed", self.name))
                    }
                    Err(_) => Err(format!(
                        "hook '{}' is quarantined past the call's budget",
                        self.name
                    )),
                };
            }
            tokio::time::sleep(wait).await;
        }
    }

    fn trial(&self, window: Duration) -> Result<Arc<Plugin<Hook>>, String> {
        let recoverable = {
            let configured = self.configured.lock().unwrap_or_else(|e| e.into_inner());
            if configured.pending != 0 || configured.uncertain {
                Err("hook configuration result is unresolved; recovery is unavailable".to_owned())
            } else {
                Ok(())
            }
        };
        let opened = recoverable.and_then(|()| {
            (self.rebind)().and_then(|p| {
                if p.context::<HookContext>()
                    .is_none_or(|context| context.routes != self.routes)
                {
                    return Err("hook route declarations changed during recovery".into());
                }
                open(&p, &self.settings)?;
                Ok(Arc::new(p))
            })
        });
        let opened = opened.and_then(|p| loop {
            let saved = {
                let configured = self.configured.lock().unwrap_or_else(|e| e.into_inner());
                if configured.pending != 0 || configured.uncertain {
                    Err("hook configuration result is unresolved; recovery is unavailable")
                } else {
                    Ok(configured.kept.clone())
                }
            };
            let saved = match saved {
                Ok(saved) => saved,
                Err(error) => {
                    close(&p);
                    return Err(error.to_owned());
                }
            };
            let restored = match saved
                .as_ref()
                .map(|saved| reconfigure(&p, saved))
                .transpose()
            {
                Ok(restored) => restored,
                Err(error) => {
                    close(&p);
                    return Err(error);
                }
            };

            let mut state = self.lock();
            let mut configured = self.configured.lock().unwrap_or_else(|e| e.into_inner());
            if configured.pending != 0 || configured.uncertain {
                drop(configured);
                drop(state);
                close(&p);
                return Err(
                    "hook configuration result is unresolved; recovery is unavailable".into(),
                );
            }
            let unchanged = match (&saved, &configured.kept) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            };
            if !unchanged {
                continue;
            }
            configured.owner = Arc::downgrade(&p);
            configured.kept = saved.as_ref().map(|saved| {
                Arc::new(Configured {
                    name: saved.name.clone(),
                    checkpoint: restored,
                })
            });
            *state = State::Live {
                plugin: Arc::clone(&p),
                next_fault_window: (window * 2).min(QUARANTINE_MAX),
            };
            return Ok(p);
        });
        if let Err(error) = &opened {
            let window = (window * 2).min(QUARANTINE_MAX);
            *self.lock() = State::Quarantined {
                trial_at: Instant::now() + window,
                window,
            };
            return Err(format!(
                "hook '{}' is quarantined: its trial did not open: {error}",
                self.name
            ));
        }
        opened
    }

    fn acknowledged(
        &self,
        plugin: &Arc<Plugin<Hook>>,
        name: &str,
        version: u64,
        checkpoint: Result<Option<ConfigureCheckpoint>, String>,
    ) -> Result<(), String> {
        let mut configured = self.configured.lock().unwrap_or_else(|e| e.into_inner());
        if !configured.owner.ptr_eq(&Arc::downgrade(plugin)) {
            return Err("hook configuration was acknowledged by a retired instance".into());
        }

        if configured
            .kept
            .as_ref()
            .is_some_and(|kept| kept.checkpoint.is_none())
        {
            return checkpoint.map(|_| ());
        }
        let checkpoint = checkpoint.and_then(|value| {
            if value.as_ref().is_some_and(|v| v.settings_version < version) {
                Err("hook configuration checkpoint predates its acknowledgement".into())
            } else {
                Ok(value)
            }
        });
        if let Ok(Some(next)) = &checkpoint {
            if let Some(previous) = configured.kept.as_ref().and_then(|k| k.checkpoint.as_ref()) {
                if next.revision < previous.revision {
                    if next.settings_version <= previous.settings_version {
                        return Ok(());
                    }
                    configured.kept = Some(Arc::new(Configured {
                        name: name.to_owned(),
                        checkpoint: None,
                    }));
                    return Err("hook configuration checkpoint order is inconsistent".into());
                }
                if next.settings_version < previous.settings_version {
                    configured.kept = Some(Arc::new(Configured {
                        name: name.to_owned(),
                        checkpoint: None,
                    }));
                    return Err("hook configuration checkpoint version moved backwards".into());
                }
                if next.revision == previous.revision {
                    if next.settings_version == previous.settings_version
                        && next.settings() == previous.settings()
                    {
                        return Ok(());
                    }
                    configured.kept = Some(Arc::new(Configured {
                        name: name.to_owned(),
                        checkpoint: None,
                    }));
                    return Err("hook reused a configuration checkpoint revision".into());
                }
            }
        }
        let (checkpoint, error) = match checkpoint {
            Ok(checkpoint) => (checkpoint, None),
            Err(error) => (None, Some(error)),
        };
        configured.kept = Some(Arc::new(Configured {
            name: name.to_owned(),
            checkpoint,
        }));
        error.map_or(Ok(()), Err)
    }

    fn faulted(&self, plugin: &Plugin<Hook>) {
        if !plugin.is_faulted() {
            return;
        }
        {
            let mut state = self.lock();
            let window = match &*state {
                State::Live {
                    plugin: current,
                    next_fault_window,
                } if std::ptr::eq(current.as_ref(), plugin) => Some(*next_fault_window),

                _ => None,
            };
            if let Some(window) = window {
                *state = State::Quarantined {
                    trial_at: Instant::now() + window,
                    window,
                };
            }
        }

        close(plugin);
    }

    fn served(&self, plugin: &Plugin<Hook>, op: u32) {
        if !matches!(
            op,
            slot::DECIDE | slot::TRANSFORM | slot::SERVE | slot::NOTIFY
        ) {
            return;
        }
        let mut state = self.lock();
        if let State::Live {
            plugin: current,
            next_fault_window,
        } = &mut *state
        {
            if std::ptr::eq(current.as_ref(), plugin) && !plugin.is_faulted() {
                *next_fault_window = QUARANTINE_FIRST;
            }
        }
    }

    async fn submit<I, O>(
        self: &Arc<Self>,
        s: u32,
        budget: Duration,
        lent: Lent,
        make: impl Fn() -> Frame<I, O> + Send,
        regrow: impl FnMut(&O) -> Option<Lent> + Send,
    ) -> Result<Submitted<O>, Answered<O>>
    where
        I: InFrame,
        O: OutFrame + Copy,
    {
        self.submit_tracked(s, budget, lent, make, regrow, None)
            .await
    }

    async fn submit_tracked<I, O>(
        self: &Arc<Self>,
        s: u32,
        budget: Duration,
        lent: Lent,
        make: impl Fn() -> Frame<I, O> + Send,
        mut regrow: impl FnMut(&O) -> Option<Lent> + Send,
        mut configure: Option<&mut ConfigureAttempt>,
    ) -> Result<Submitted<O>, Answered<O>>
    where
        I: InFrame,
        O: OutFrame + Copy,
    {
        let deadline = Instant::now().checked_add(budget).ok_or_else(|| {
            Answered::Broken(format!(
                "hook '{}' call budget exceeds the clock range",
                self.name
            ))
        })?;
        let deadline_ns =
            now_ns().saturating_add(u64::try_from(budget.as_nanos()).unwrap_or(u64::MAX));
        let mut lent = lent;
        let mut first = true;
        'route: loop {
            let plugin = self.live(deadline).await.map_err(Answered::Broken)?;
            let workers = self.dispatcher.workers().max(1);
            let worker = self.next_worker.fetch_add(1, Ordering::Relaxed) % workers;

            let Some(call) = Ticketed::mint(&self.dispatcher, worker) else {
                return Err(Answered::Broken(format!(
                    "hook '{}' could not be called: no ticket",
                    self.name
                )));
            };
            let mut call = call.watched(budget);
            let mut slot_wait = SLOT_WAIT_FIRST;
            let mut retried_free = false;
            loop {
                if plugin.is_faulted() {
                    continue 'route;
                }
                if let Some(attempt) = configure.as_deref_mut() {
                    attempt.target(&plugin).map_err(Answered::Broken)?;
                }
                call.submit(
                    &*plugin,
                    s,
                    make(),
                    DeadlineClass::Call,
                    deadline_ns,
                    Arc::clone(&lent),
                );

                let Ok(done) = tokio::time::timeout(
                    deadline.saturating_duration_since(Instant::now()),
                    &mut call,
                )
                .await
                else {
                    return Err(Answered::TimedOut);
                };

                if done.outcome == Outcome::Refused {
                    if let Some(attempt) = configure.as_deref_mut() {
                        attempt.finish(true);
                    }
                }

                #[cfg(test)]
                if done.outcome == Outcome::Refused {
                    hold_refused_until_faulted_for_tests(&self.settings, &plugin, deadline).await;
                }

                if done.outcome == Outcome::Refused && plugin.is_faulted() {
                    continue 'route;
                }
                if done.outcome == Outcome::Refused {
                    if plugin.inflight() < plugin.max_inflight() {
                        if !retried_free {
                            retried_free = true;
                            continue;
                        }
                    } else {
                        let left = deadline.saturating_duration_since(Instant::now());
                        if left.is_zero() {
                            return Err(Answered::TimedOut);
                        }
                        tokio::time::sleep(slot_wait.min(left)).await;
                        slot_wait = (slot_wait * 2).min(SLOT_WAIT_MAX);
                        retried_free = false;
                        continue;
                    }
                }
                let out = done.frame.as_ref().map(|f| f.out);
                if done.short && first {
                    if let Some(grown) = out.as_ref().and_then(&mut regrow) {
                        first = false;
                        lent = grown;
                        continue;
                    }
                }
                return match (done.outcome, out) {
                    (Outcome::Ready | Outcome::Failed, _) if done.disposition.is_some() => {
                        Err(Answered::TimedOut)
                    }
                    (Outcome::Ready | Outcome::Failed, Some(out)) => {
                        if done.outcome == Outcome::Ready && !done.short {
                            self.served(&plugin, s);
                        }
                        Ok(Submitted {
                            plugin,
                            outcome: done.outcome,
                            out,
                            error: text(done.error),
                            lease: done.lease,
                            lent,
                        })
                    }
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
}

#[cfg(test)]
pub(crate) static HOLD_REFUSED_UNTIL_FAULTED_FOR_TESTS: Mutex<Option<Vec<u8>>> = Mutex::new(None);

#[cfg(test)]
async fn hold_refused_until_faulted_for_tests(
    settings: &[u8],
    plugin: &Plugin<Hook>,
    deadline: Instant,
) {
    let held = HOLD_REFUSED_UNTIL_FAULTED_FOR_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_deref()
        .is_some_and(|mark| settings.windows(mark.len()).any(|w| w == mark));
    while held && !plugin.is_faulted() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

struct Submitted<O> {
    plugin: Arc<Plugin<Hook>>,
    outcome: Outcome,
    out: O,
    error: Option<String>,
    lease: u64,

    lent: Lent,
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
        if let State::Live { plugin, .. } = self.state.get_mut().unwrap_or_else(|p| p.into_inner())
        {
            close(plugin);
        }
    }
}

impl HookInstance {
    pub fn open(
        plugin: Plugin<Hook>,
        dispatcher: Arc<Dispatcher>,
        settings: &[u8],
        rebind: impl Fn() -> Result<Plugin<Hook>, String> + Send + Sync + 'static,
    ) -> Result<Self, String> {
        Self::open_declaring(plugin, dispatcher, settings, true, rebind)
    }

    pub fn open_declaring(
        plugin: Plugin<Hook>,
        dispatcher: Arc<Dispatcher>,
        settings: &[u8],
        orders: bool,
        rebind: impl Fn() -> Result<Plugin<Hook>, String> + Send + Sync + 'static,
    ) -> Result<Self, String> {
        open(&plugin, settings)?;
        let plugin = Arc::new(plugin);
        Ok(Self {
            inner: Arc::new(Inner {
                name: plugin.name().to_string(),
                routes: plugin
                    .context::<HookContext>()
                    .map_or_else(Vec::new, |f| f.routes.clone()),
                dispatcher,
                rebind: Box::new(rebind),
                settings: zeroize::Zeroizing::new(settings.to_vec()),
                configured: Mutex::new(Configuration {
                    owner: Arc::downgrade(&plugin),
                    kept: None,
                    pending: 0,
                    uncertain: false,
                }),
                state: Mutex::new(State::Live {
                    plugin,
                    next_fault_window: QUARANTINE_FIRST,
                }),
                next_worker: AtomicU32::new(0),
                orders,
            }),
        })
    }

    #[must_use]
    pub fn quarantined(&self) -> bool {
        match &*self.inner.lock() {
            State::Live { plugin, .. } => plugin.is_faulted(),
            State::Quarantined { .. } | State::Trialing => true,
        }
    }

    fn verdict<O>(&self, s: u32, frame: Arc<DecideFrame>, budget: Duration) -> Pending<Answered<O>>
    where
        O: OutFrame + Copy + 'static,
    {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let Some(lent) = frame.try_lend().map(Arc::new) else {
                return Answered::Broken("hook answer buffers are already in use".into());
            };
            let current = Arc::new(Mutex::new(Arc::clone(&lent)));
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
                    let previous = current.lock().unwrap_or_else(|p| p.into_inner()).clone();
                    let grown = regrown(previous.frame(), s, out)?;
                    let grown = Arc::new(grown.try_lend()?);
                    // The SHORT answer ended the old operation before this fresh re-call.
                    // SAFETY: submit invokes regrow only after receiving the settled answer.
                    unsafe { previous.complete() };
                    let retired = {
                        let mut c = current.lock().unwrap_or_else(|p| p.into_inner());
                        std::mem::replace(&mut *c, Arc::clone(&grown))
                    };
                    drop(retired);
                    Some(grown as Lent)
                }
            };
            match inner.submit(s, budget, lent as Lent, make, regrow).await {
                Ok(done) => {
                    release(&done.plugin, done.lease);
                    if !inner.orders && done.outcome == Outcome::Ready {
                        if let Some(refused) = refused_order(s, &done.out, &inner.name) {
                            return Answered::Broken(refused);
                        }
                    }
                    let lent = current.lock().unwrap_or_else(|p| p.into_inner()).clone();
                    // SAFETY: submit returned the terminal answer, after the last crossing.
                    // Unlike timeout/client drop, this establishes that plugin writes ended.
                    unsafe { lent.complete() };
                    let frame = Arc::clone(lent.frame());
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

fn refused_order<O: 'static>(s: u32, out: &O, name: &str) -> Option<String> {
    if s != slot::DECIDE {
        return None;
    }
    let out: &dyn std::any::Any = out;
    let o = out.downcast_ref::<DecideOut>()?;
    (o.verbs & VERB_PREFER != 0 || o.order_written > 0 || o.order_needed > 0).then(|| {
        format!(
            "hook plugin '{name}' declared `hook.orders: false` and answered an order: its \
             `decide` must always abstain, so the order is refused"
        )
    })
}

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

    fn routes(&self) -> &[Route] {
        &self.inner.routes
    }

    fn serve(
        &self,
        request: EndpointRequest,
        budget: Duration,
    ) -> Pending<Result<EndpointResponse, String>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let lent = Arc::new(ServeLent::new(request));
            let make = {
                let lent = Arc::clone(&lent);
                move || Frame::new(lent.input(), blank_out::<ServeOut>())
            };
            let done = match inner
                .submit(slot::SERVE, budget, lent as Lent, make, |_: &ServeOut| None)
                .await
            {
                Ok(done) => done,
                Err(Answered::TimedOut) => return Err("hook serve exceeded its budget".into()),
                Err(Answered::Broken(why)) => return Err(why),
                Err(Answered::Answer { .. }) => {
                    return Err("hook serve answered out of turn".into())
                }
            };
            if done.outcome != Outcome::Ready {
                release(&done.plugin, done.lease);
                return Err(done.error.unwrap_or_else(|| "hook serve failed".into()));
            }
            if done.out.headers_out_len % 2 != 0 {
                release(&done.plugin, done.lease);
                return Err("hook serve returned an unpaired response header".into());
            }
            let pairs = if done.out.headers_out_len == 0 {
                &[][..]
            } else {
                // SAFETY: the kind's check_serve bounded this non-null list. Its lease is
                // retained until all response bytes have been copied below.
                unsafe {
                    std::slice::from_raw_parts(done.out.headers_out, done.out.headers_out_len)
                }
            };
            let response = pairs
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[k, v]| Ok((copy_serve_text(*k)?, copy_serve_text(*v)?)))
                .collect::<Result<Vec<_>, String>>()
                .map(|headers| EndpointResponse {
                    status: done.out.status_code,
                    headers,
                    body: copy_blob(done.out.body),
                });
            release(&done.plugin, done.lease);
            response
        })
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
            if let Ok(done) = inner
                .submit(
                    slot::NOTIFY,
                    budget,
                    frame as Lent,
                    move || Frame::new(held.get(), out_head()),
                    |_: &OutHead| None,
                )
                .await
            {
                release(&done.plugin, done.lease);
            }
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
        let owned: Pushed = Arc::new((
            name.to_string(),
            zeroize::Zeroizing::new(settings.as_bytes().to_vec()),
            version,
        ));
        Box::pin(async move {
            let lent = Arc::clone(&owned);
            let acked = Arc::clone(&owned);
            let make = move || {
                Frame::new(
                    ConfigureIn {
                        head: in_head(),
                        version,
                        settings: json(&lent.1),
                        name: lend_or_null(&lent.0),
                    },
                    blank_out::<ConfigureOut>(),
                )
            };
            let hook = inner.name.clone();
            let mut attempt = ConfigureAttempt {
                inner: Arc::clone(&inner),
                target: None,
            };
            match inner
                .submit_tracked(
                    slot::CONFIGURE,
                    budget,
                    owned as Lent,
                    make,
                    |_: &ConfigureOut| None,
                    Some(&mut attempt),
                )
                .await
            {
                Ok(done) if done.outcome == Outcome::Ready && done.out.acked_version == version => {
                    let checkpoint = checkpoint(&done.out);
                    release(&done.plugin, done.lease);
                    let result = inner.acknowledged(&done.plugin, &acked.0, version, checkpoint);
                    attempt.finish(true);
                    result
                }
                Ok(done) => {
                    release(&done.plugin, done.lease);
                    if done.outcome == Outcome::Failed {
                        attempt.finish(true);
                    }

                    Err(done.error.map_or_else(
                        || format!("hook '{hook}' did not acknowledge settings version {version}"),
                        |why| format!("hook '{hook}': {why}"),
                    ))
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

struct ServeLent {
    request: EndpointRequest,
    headers: Vec<busbar_contract::abi::mechanism::call::AbiStr>,
}

// SAFETY: the header pointers address immutable strings owned by request. Moving this value
// moves the Vec/String handles, never their allocations; the dispatcher retains its Arc.
unsafe impl Send for ServeLent {}
// SAFETY: shared access only lends immutable request bytes while the Arc remains alive.
unsafe impl Sync for ServeLent {}

impl ServeLent {
    fn new(request: EndpointRequest) -> Self {
        let headers = request
            .headers
            .iter()
            .flat_map(|(k, v)| [lend_or_null(k), lend_or_null(v)])
            .collect();
        Self { request, headers }
    }

    fn input(&self) -> ServeIn {
        ServeIn {
            head: in_head(),
            method: lend_or_null(&self.request.method),
            path: lend_or_null(&self.request.path),
            query: lend_or_null(&self.request.query),
            headers: if self.headers.is_empty() {
                std::ptr::null()
            } else {
                self.headers.as_ptr()
            },
            headers_len: self.headers.len(),
            body: blob(
                &self.request.body,
                busbar_contract::abi::mechanism::call::BLOB_OCTETS,
                0,
            ),
        }
    }
}

impl Drop for ServeLent {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.request.query.zeroize();
        self.request.body.zeroize();
        for (name, value) in &mut self.request.headers {
            name.zeroize();
            value.zeroize();
        }
    }
}

fn copy_serve_text(value: busbar_contract::abi::mechanism::call::AbiStr) -> Result<String, String> {
    let bytes = crate::dispatch::plugin::str_bytes(value)
        .ok_or_else(|| "hook serve returned a malformed response header".to_string())?;
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| "hook serve returned a non-UTF8 response header".into())
}

struct Held<T>(T);
// SAFETY: the pointers inside point at data the same future owns or lends to the op for its whole
// life; one thread touches the future at a time.
unsafe impl<T> Send for Held<T> {}
impl<T: Copy> Held<T> {
    fn get(&self) -> T {
        self.0
    }
}

fn claims(c: &Candidate, word: &str) -> bool {
    busbar_contract::abi::mechanism::rendering::read(&c.stated).is_ok_and(|r| {
        r.mark_words
            .iter()
            .any(|(class, w)| *class == MARK_WORD_HOOK && w == word)
    })
}

fn answers(c: &Candidate, module: &str) -> bool {
    c.answers(module) || claims(c, module)
}

#[must_use]
pub fn dropped_answers(registry: &PluginRegistry, module: &str) -> bool {
    registry
        .dropped_hooks()
        .any(|p| matches!(p.candidate(), Ok(Some(c)) if answers(&c, module)))
}

pub struct HookRows {
    candidates: Vec<Candidate>,

    first_party: Vec<String>,
    dispatcher: Arc<Dispatcher>,

    logs: Option<PluginLogConfig>,

    conns: Option<fn() -> Arc<dyn DeclaredConns>>,
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
        for p in registry.into_iter().flat_map(PluginRegistry::dropped_hooks) {
            let Some(c) = p.candidate()? else {
                return Err(format!("plugin '{}': {JSON_HOOK_REFUSED}", p.manifest.name));
            };
            if p.first_party() {
                first_party.push(c.name.clone());
            }
            candidates.push(c);
        }
        crate::boot::one_owner(&candidates)?;
        for line in crate::boot::both_doors(&candidates) {
            tracing::info!("{line}");
        }
        let mut rows = Self::of(candidates, dispatcher);
        rows.first_party = first_party;
        Ok(rows)
    }

    pub fn with_former_names(
        mut self,
        former_of: impl Fn(&str) -> Vec<String>,
    ) -> Result<Self, String> {
        for c in &mut self.candidates {
            if matches!(c.origin, Origin::Linked(_)) {
                *c = c.clone().answering_former(&former_of);
            }
        }
        crate::boot::one_owner(&self.candidates)?;
        Ok(self)
    }

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

    #[must_use]
    pub fn with_logs(mut self, logs: PluginLogConfig) -> Self {
        self.logs = Some(logs);
        self
    }

    #[must_use]
    pub fn with_conns(mut self, conns: fn() -> Arc<dyn DeclaredConns>) -> Self {
        self.conns = Some(conns);
        self
    }

    fn find(&self, module: &str) -> Option<&Candidate> {
        self.candidates.iter().find(|c| answers(c, module))
    }

    fn bind(
        c: &Candidate,
        dispatcher: &Dispatcher,
        label: &str,
        sink: Arc<dyn EnvelopeSink>,
        conns: ConnTable,
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
    fn routes(
        &self,
        module: &str,
        instance: &str,
        settings: &serde_json::Value,
    ) -> Result<Vec<Route>, String> {
        let Some(candidate) = self.find(module) else {
            return Ok(Vec::new());
        };
        let refused = |e| format!("hook plugin '{}': {e}", candidate.name);
        let image = match &candidate.origin {
            Origin::Linked(row) => crate::dispatch::load::prepare_linked::<Hook>(row),
            Origin::Dropped { file, bytes } => {
                crate::dispatch::load::prepare_dropped_bytes::<Hook>(bytes, file, &candidate.stated)
            }
        }
        .map_err(refused)?;
        let routes = image.routes().map_err(refused)?;
        if !routes.is_empty() {
            let plugin = image
                .bind(Bind {
                    instance: Arc::from(instance),
                    max_inflight_cap: MAX_INFLIGHT_CAP,
                    sink: Arc::new(NoSink),
                    dispatcher: self.dispatcher.adopter(),
                    conns: ConnTable::Probe,
                })
                .map_err(refused)?;
            let text = zeroize::Zeroizing::new(settings.to_string());
            validate(&plugin, text.as_bytes())?;
        }
        Ok(routes)
    }

    fn probe(&self, module: &str, instance: &str, settings: &serde_json::Value) -> Option<Probed> {
        let c = self.find(module)?;

        let Ok(p) = Self::bind(
            c,
            &self.dispatcher,
            instance,
            Arc::new(NoSink),
            ConnTable::Probe,
        ) else {
            return Some((None, Vec::new()));
        };
        let facts = p
            .context::<HookContext>()
            .map(|context| context.facts.clone());
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
        let conns = ConnTable::serving(self.conns.map(|table| table()));
        let c_orders = c.orders;
        let plugin = Self::bind(&c, &self.dispatcher, label, sink(label)?, conns.clone())?;
        let rebind = {
            let (dispatcher, label) = (Arc::clone(&self.dispatcher), label.to_string());
            let sink = sink(label.as_str())?;
            move || Self::bind(&c, &dispatcher, &label, Arc::clone(&sink), conns.clone())
        };
        let text = settings.to_string();
        let opened = HookInstance::open_declaring(
            plugin,
            Arc::clone(&self.dispatcher),
            text.as_bytes(),
            c_orders,
            rebind,
        )?;
        Ok(Arc::new(opened))
    }

    fn linked(&self, module: &str) -> bool {
        self.find(module)
            .is_some_and(|c| matches!(c.origin, Origin::Linked(_)))
    }

    fn call_budget(&self) -> Duration {
        self.dispatcher.budgets().call
    }

    fn first_party(&self, module: &str) -> bool {
        self.find(module).is_some_and(|c| {
            matches!(c.origin, Origin::Linked(_)) || self.first_party.contains(&c.name)
        })
    }
}

#[cfg(test)]
#[path = "tests/hook_door_tests.rs"]
mod tests;
