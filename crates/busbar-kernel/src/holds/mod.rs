// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The CA-5 hold (IF §12.29, W2-K8P): `Holds`, one config generation's index from an inbound auth instance to the
//! `HoldSet`s of the provisioning instances that link it, and `HoldSet`, one provisioning instance's held principals.
//!
//! Consistency model (frozen): `held_ns` in the store is the truth (the kernel directory, W1-K6P, is its only
//! writer); each replica keeps its `HoldSet` as a snapshot of it. (a) Boot and each config generation load the
//! snapshot with a full scan before the generation serves; a store failure refuses the boot, and refuses a reload
//! that adds or changes the provisioning instance (an unchanged instance keeps its snapshot). (b) One refresh task
//! per `HoldSet` reads the store's generation of `held_ns` every `link.refresh_ms` and rescans only when it moved.
//! (c) A write on this replica that changes `held_ns` calls [`HoldSet::after_write`] before the DIRECTORY Need
//! answers, so the writing node holds at once. Another replica holds a principal at most `refresh_ms` plus one
//! rescan after the commit that made it INACTIVE.
//!
//! The request path costs one Relaxed load when nothing is held, else one `ArcSwap::load` and one foldhash probe:
//! no lock, no allocation, no await (B-HOLD).

pub mod guard;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use foldhash::fast::RandomState;
use tokio::sync::{Mutex, Notify};

use crate::config::min3::{ProvisioningCfg, ProvisioningLink};
use crate::directory::MAX_HELD;

/// Rows per page of a full rescan of `held_ns` (IF §12.29 (b)).
pub const RESCAN_PAGE: u32 = 500;
/// Consecutive failed refreshes after which `provisioning_hold_stale` is raised.
pub const STALE_AFTER: u32 = 3;
/// Counted on every failed refresh, labelled by provisioning instance.
pub const HOLD_REFRESH_FAILED_TOTAL: &str = "provisioning_hold_refresh_failed_total";
/// 1 while a `HoldSet` has failed [`STALE_AFTER`] refreshes in a row, else 0, labelled by provisioning instance.
pub const HOLD_STALE: &str = "provisioning_hold_stale";

type Set = HashSet<Box<str>, RandomState>;

/// Why a load or refresh of `held_ns` did not complete. The last snapshot is kept either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldFault {
    /// The store did not answer (or answered a fault).
    Store,
    /// `held_ns` holds more than [`MAX_HELD`] principals (the directory refuses such a write, so this is a store
    /// written by something else).
    TooMany,
}

/// One page of `held_ns`, in key order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeldPage {
    /// The held principals (the keys of `held_ns`).
    pub principals: Vec<Box<str>>,
    /// The last key of this page when the store reported continuation; None = the scan is complete.
    pub next: Option<Box<str>>,
}

/// The read side of one provisioning instance's `held_ns`, implemented by the kernel directory (W1-K6P) over the
/// core store. Both reads are plain store scans; neither writes.
pub trait HeldSource: Send + Sync + 'static {
    /// The store's generation of `held_ns`: one scan with `max_rows` 1, its SCAN_DONE `generation` (§8.1).
    fn generation(&self) -> impl Future<Output = Result<u64, HoldFault>> + Send;
    /// At most `max_rows` keys of `held_ns` after `after` (exclusive; None = from the start).
    fn page(
        &self,
        after: Option<&str>,
        max_rows: u32,
    ) -> impl Future<Output = Result<HeldPage, HoldFault>> + Send;
}

/// What a `HoldSet` reports. [`CoreHoldEvents`] is the production sink; tests count.
pub trait HoldEvents: Send + Sync + 'static {
    /// A held principal was refused (audit `principal_held{instance}`). Never carries the principal or a credential.
    fn held(&self, instance: &str);
    /// A refresh failed; `consecutive` counts this one.
    fn refresh_failed(&self, instance: &str, consecutive: u32);
    /// The set went stale (`consecutive == STALE_AFTER`) or recovered (`stale == false`).
    fn stale(&self, instance: &str, stale: bool);
}

/// Audit rows on the admin chain, counters and the stale gauge.
#[derive(Clone, Copy, Debug, Default)]
pub struct CoreHoldEvents;

impl HoldEvents for CoreHoldEvents {
    fn held(&self, instance: &str) {
        crate::audit::auditlog::emit_admin_hostless_now(
            "principal_held",
            &format!("provisioning:{instance}"),
            busbar_contract::vocab::OUTCOME_REFUSED,
            crate::audit::auditlog::PLUGIN_REFUSAL_PRINCIPAL,
        );
    }

    fn refresh_failed(&self, instance: &str, _consecutive: u32) {
        metrics::counter!(HOLD_REFRESH_FAILED_TOTAL, "instance" => instance.to_string()).increment(1);
    }

    fn stale(&self, instance: &str, stale: bool) {
        metrics::gauge!(HOLD_STALE, "instance" => instance.to_string()).set(if stale {
            1.0
        } else {
            0.0
        });
        if stale {
            crate::audit::auditlog::emit_admin_hostless_now(
                HOLD_STALE,
                &format!("provisioning:{instance}"),
                busbar_contract::vocab::OUTCOME_DEGRADED,
                crate::audit::auditlog::PLUGIN_REFUSAL_PRINCIPAL,
            );
        }
    }
}

/// One provisioning instance's held principals (the `link.index` values of its INACTIVE subjects).
pub struct HoldSet {
    instance: Box<str>,
    link: ProvisioningLink,
    len: AtomicU32,
    set: ArcSwap<Set>,
    /// Wakes the refresh task early (a local write that did not wait for its swap, or a shutdown nudge).
    wake: Notify,
    /// The store generation the current snapshot was scanned at.
    generation: AtomicU64,
    loaded: AtomicBool,
    started: AtomicBool,
    failures: AtomicU32,
    /// Serialises rescans so an older scan never swaps over a newer one. Never taken on the request path.
    rescan: Mutex<()>,
    events: Arc<dyn HoldEvents>,
}

impl HoldSet {
    /// An empty, unloaded set for provisioning instance `instance` with link `link`.
    pub fn new(instance: &str, link: ProvisioningLink, events: Arc<dyn HoldEvents>) -> Self {
        Self {
            instance: instance.into(),
            link,
            len: AtomicU32::new(0),
            set: ArcSwap::from_pointee(Set::default()),
            wake: Notify::new(),
            generation: AtomicU64::new(0),
            loaded: AtomicBool::new(false),
            started: AtomicBool::new(false),
            failures: AtomicU32::new(0),
            rescan: Mutex::new(()),
            events,
        }
    }

    /// true = `principal` is held. Sync, no allocation, no lock, no await: one Relaxed load of `len` (0 = false);
    /// otherwise one `ArcSwap::load` (2 RMWs on the caller's own debt slot, §0 I5's fourth exception) and one
    /// foldhash probe of the principal bytes. B-HOLD (§14).
    pub fn holds(&self, principal: &str) -> bool {
        if self.len.load(Ordering::Relaxed) == 0 {
            return false;
        }
        self.set.load().contains(principal)
    }

    /// The provisioning instance this set belongs to.
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// The `provisioning.link` the set was built from.
    pub fn link(&self) -> &ProvisioningLink {
        &self.link
    }

    /// Held principals in the current snapshot.
    pub fn len(&self) -> u32 {
        self.len.load(Ordering::Acquire)
    }

    /// true = nothing is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The store generation of the current snapshot (0 before the first load).
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn swap(&self, set: Set, generation: u64) {
        let n = set.len() as u32;
        // Store first, then len: a reader that sees the new len always finds the new set.
        self.set.store(Arc::new(set));
        self.len.store(n, Ordering::Release);
        self.generation.store(generation, Ordering::Release);
        self.loaded.store(true, Ordering::Release);
    }

    async fn scan<S: HeldSource>(source: &S) -> Result<Set, HoldFault> {
        let mut set = Set::default();
        let mut after: Option<Box<str>> = None;
        loop {
            let page = source.page(after.as_deref(), RESCAN_PAGE).await?;
            if set.len() + page.principals.len() > MAX_HELD as usize {
                return Err(HoldFault::TooMany);
            }
            set.extend(page.principals);
            match page.next {
                Some(next) => after = Some(next),
                None => return Ok(set),
            }
        }
    }

    /// The full load (boot or a new or changed generation): scans `held_ns` whatever the generation and swaps it
    /// in. Err = the snapshot is unchanged and the caller refuses the boot or the reload.
    pub async fn load<S: HeldSource>(&self, source: &S) -> Result<(), HoldFault> {
        let _one = self.rescan.lock().await;
        let generation = source.generation().await?;
        let set = Self::scan(source).await?;
        self.swap(set, generation);
        Ok(())
    }

    /// One refresh: read the generation; when it moved (or nothing was loaded yet), rescan and swap. A failure
    /// keeps the last snapshot, is counted, and after [`STALE_AFTER`] in a row raises `provisioning_hold_stale`.
    pub async fn refresh<S: HeldSource>(&self, source: &S) -> Result<bool, HoldFault> {
        let outcome = self.refresh_inner(source).await;
        match outcome {
            Ok(_) => {
                if self.failures.swap(0, Ordering::AcqRel) >= STALE_AFTER {
                    self.events.stale(&self.instance, false);
                }
            }
            Err(_) => {
                let n = self.failures.fetch_add(1, Ordering::AcqRel) + 1;
                self.events.refresh_failed(&self.instance, n);
                if n == STALE_AFTER {
                    self.events.stale(&self.instance, true);
                }
            }
        }
        outcome
    }

    async fn refresh_inner<S: HeldSource>(&self, source: &S) -> Result<bool, HoldFault> {
        let _one = self.rescan.lock().await;
        let generation = source.generation().await?;
        if self.loaded.load(Ordering::Acquire) && generation == self.generation() {
            return Ok(false);
        }
        // The generation is read before the scan: a commit landing mid-scan moves it again, so the next refresh
        // rescans; a snapshot is never labelled newer than what it read.
        let set = Self::scan(source).await?;
        self.swap(set, generation);
        Ok(true)
    }

    /// Called by the kernel directory after a commit on this replica that changed `held_ns`, before the DIRECTORY
    /// Need answers: the local snapshot is swapped before this returns, so the writing node holds at once. A failed
    /// rescan is counted like any refresh, and the refresh task is woken to retry.
    pub async fn after_write<S: HeldSource>(&self, source: &S) -> Result<(), HoldFault> {
        let out = self.refresh(source).await.map(|_| ());
        if out.is_err() {
            self.wake.notify_one();
        }
        out
    }

    /// Wakes the refresh task now (a local write that does not wait for its swap).
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// Starts this set's one refresh task (no-op when it already runs, so an unchanged set carried into a new
    /// generation keeps its task). The task holds a weak reference and ends within `refresh_ms` of the last
    /// generation dropping the set.
    pub fn spawn_refresh<S: HeldSource>(self: &Arc<Self>, source: Arc<S>) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak: Weak<Self> = Arc::downgrade(self);
        let every = Duration::from_millis(u64::from(self.link.refresh_ms.max(1)));
        tokio::spawn(async move {
            loop {
                let Some(me) = weak.upgrade() else { return };
                tokio::select! {
                    _ = tokio::time::sleep(every) => {}
                    _ = me.wake.notified() => {}
                }
                let _ = me.refresh(&*source).await;
            }
        });
    }
}

/// Why a generation's `Holds` could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HoldsBuildError {
    /// The full load of a new or changed provisioning instance failed: the boot or the reload is refused.
    Load {
        instance: Box<str>,
        fault: HoldFault,
    },
    /// A `link.auth` name is not a configured inbound auth instance (the config load refuses it first, W1-K6P).
    UnknownInbound { instance: Box<str>, inbound: Box<str> },
}

impl core::fmt::Display for HoldsBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Load { instance, fault } => write!(
                f,
                "auth.{instance}.provisioning: the held principals could not be loaded from the store ({fault:?}); \
                 the configuration is not applied"
            ),
            Self::UnknownInbound { instance, inbound } => write!(
                f,
                "auth.{instance}.provisioning.link.auth names `{inbound}`, which is not a configured inbound auth instance"
            ),
        }
    }
}

/// K6p, the CA-5 index. Built per config generation from every `provisioning.link`. K8p resolves `for_inbound`
/// once per generation and keeps the answer beside the inbound auth port; the request path never calls it.
#[derive(Default)]
pub struct Holds {
    by_id: HashMap<u64, Box<[Arc<HoldSet>]>, RandomState>,
    by_name: HashMap<Box<str>, Box<[Arc<HoldSet>]>, RandomState>,
    sets: BTreeMap<Box<str>, Arc<HoldSet>>,
}

impl Holds {
    /// None = no provisioning instance links `inbound`: K8p makes no probe for it at all.
    pub fn for_inbound(&self, inbound: u64) -> Option<&[Arc<HoldSet>]> {
        self.by_id.get(&inbound).map(|b| &**b)
    }

    /// [`Self::for_inbound`] by configured inbound auth instance name (a verdict names its module).
    pub fn for_inbound_name(&self, inbound: &str) -> Option<&[Arc<HoldSet>]> {
        self.by_name.get(inbound).map(|b| &**b)
    }

    /// The set of provisioning instance `instance`, when it has a `link`.
    pub fn set(&self, instance: &str) -> Option<&Arc<HoldSet>> {
        self.sets.get(instance)
    }

    /// Every set, by provisioning instance name.
    pub fn sets(&self) -> impl Iterator<Item = (&str, &Arc<HoldSet>)> {
        self.sets.iter().map(|(k, v)| (&**k, v))
    }

    /// Builds one generation. `inbound_id` resolves a configured inbound auth instance name to its id (None =
    /// not configured); `source` gives each provisioning instance's `held_ns` reader. A set whose instance and
    /// `link` are unchanged from `prev` is carried over with its snapshot and task; every other set is fully
    /// loaded here, before the generation serves, and a failed load refuses the generation.
    pub async fn build<S, I, F>(
        provisioning: &BTreeMap<Box<str>, ProvisioningCfg>,
        inbound_id: I,
        source: F,
        prev: Option<&Holds>,
        events: Arc<dyn HoldEvents>,
    ) -> Result<Self, HoldsBuildError>
    where
        S: HeldSource,
        I: Fn(&str) -> Option<u64>,
        F: Fn(&str) -> Arc<S>,
    {
        let mut sets: BTreeMap<Box<str>, Arc<HoldSet>> = BTreeMap::new();
        let mut by_name: BTreeMap<Box<str>, Vec<Arc<HoldSet>>> = BTreeMap::new();
        for (instance, cfg) in provisioning {
            let Some(link) = &cfg.link else { continue };
            let kept = prev
                .and_then(|p| p.sets.get(instance))
                .filter(|old| old.link == *link)
                .cloned();
            let set = match kept {
                Some(old) => old,
                None => {
                    let fresh = Arc::new(HoldSet::new(instance, link.clone(), events.clone()));
                    fresh
                        .load(&*source(instance))
                        .await
                        .map_err(|fault| HoldsBuildError::Load {
                            instance: instance.clone(),
                            fault,
                        })?;
                    fresh
                }
            };
            for inbound in &link.auth {
                by_name.entry(inbound.clone()).or_default().push(set.clone());
            }
            sets.insert(instance.clone(), set);
        }
        let mut by_id: HashMap<u64, Box<[Arc<HoldSet>]>, RandomState> = HashMap::default();
        let mut named: HashMap<Box<str>, Box<[Arc<HoldSet>]>, RandomState> = HashMap::default();
        for (inbound, list) in by_name {
            let Some(id) = inbound_id(&inbound) else {
                let instance = list
                    .first()
                    .map(|s| s.instance.clone())
                    .unwrap_or_default();
                return Err(HoldsBuildError::UnknownInbound { instance, inbound });
            };
            let list: Box<[Arc<HoldSet>]> = list.into_boxed_slice();
            by_id.insert(id, list.clone());
            named.insert(inbound, list);
        }
        Ok(Self {
            by_id,
            by_name: named,
            sets,
        })
    }

    /// Starts the refresh task of every set that has none (carried-over sets keep theirs).
    pub fn start<S, F>(&self, source: F)
    where
        S: HeldSource,
        F: Fn(&str) -> Arc<S>,
    {
        for (instance, set) in &self.sets {
            set.spawn_refresh(source(instance));
        }
    }
}

/// The CA-5 probe (K8p): the first set in `sets` that holds `principal`, reported (`principal_held{instance}`).
/// `sets` is what [`Holds::for_inbound`] returned for the verifying instance at config time; None costs nothing.
pub fn held_by<'a>(sets: Option<&'a [Arc<HoldSet>]>, principal: &str) -> Option<&'a str> {
    for set in sets? {
        if set.holds(principal) {
            set.events.held(&set.instance);
            return Some(&set.instance);
        }
    }
    None
}

/// The serving generation's `Holds`: one per process, published by the generation builder before the generation
/// serves (boot, then each reload). Empty = no provisioning instance links any inbound instance.
static CURRENT: ArcSwapOption<Holds> = ArcSwapOption::const_empty();

/// Publishes the generation's `Holds` (None = none).
pub fn publish(holds: Option<Arc<Holds>>) {
    CURRENT.store(holds);
}

/// The CA-5 probe for a verdict of inbound auth instance `inbound` naming `principal`, against the serving
/// generation. Some(provisioning instance) = refuse R_DENIED; no plugin is asked.
pub fn held_now(inbound: &str, principal: &str) -> Option<Box<str>> {
    let current = CURRENT.load();
    let holds = current.as_deref()?;
    held_by(holds.for_inbound_name(inbound), principal).map(Into::into)
}
