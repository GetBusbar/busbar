// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SERVE PATH'S ONE PRODUCTION COMPOSITION (ARCHITECT ruling, K1 serve path): where the
//! kernel's host services, the process's one dispatcher and the plane drivers are put together,
//! once per process. Every kind's wiring composes here; nothing else builds a `KernelServices`.
//!
//! THE HOST SERVICES ARRIVE LATE, BY DESIGN. The one dispatcher is built as the process's first act,
//! before any configuration is read (the one-dispatcher boot), while the kernel's services are
//! built from the loaded configuration (the destination guard `dest.judge` asks, among others). So the
//! dispatcher is handed a [`LateServices`]: it answers every service REFUSED, as a dispatcher with
//! no services does, until the composition installs the kernel's services, once, after the
//! configuration loads and before any plugin is bound. No plugin crosses before then in a booted
//! process, so none sees the refusal.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::{Body, Bytes};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome as AbiOutcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};
use busbar_contract::caps::{OpClassId, ReasonCode};
use busbar_contract::plane::{declares_record_kind, PlaneDeclaration};
use busbar_contract::plane_calls::PlaneCalls;
use busbar_contract::services::{
    Caller, DiskDest, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Stored,
};
use busbar_kernel::host_records::QUEUE_CAP;
use busbar_kernel::host_services::{BlockingPool, DestJudge, KernelServices, SignKey};
use busbar_kernel::plane::store::KIND_DEMOTION;
use busbar_kernel::plane::DemotionRecord;
use busbar_kernel::plane_driver::serve::{publish, ServeRoute, ServeTable};
use busbar_kernel::plane_driver::{
    refusal_status, BufferCaps, CallerEnd, DriverConfig, Egress, HeadFields, MoneySeam,
    PlaneDriver, PlaneMoney, Rendered, SessionCaller,
};
use tokio::sync::{mpsc, oneshot};

use crate::root::boot::DoorPlane;
use crate::root::door_steps::{door_facts, DoorFacts, DoorPools};
use crate::root::loader::dispatch::kinds::plane::OwnedSnapshot;
use crate::root::loader::dispatch::plane_calls::PlaneInstance;
// The data routes drive their units on the node: what only they name.
#[cfg(linked_axis_node)]
use crate::root::door_steps::{egress_pool, DoorCaller, DoorSteps};
use crate::root::loader::dispatch::{in_head, out_head, Dispatcher, Frame};
#[cfg(linked_axis_node)]
use busbar_contract::abi::host::conn::connector::NEVER_KEPT;
#[cfg(linked_axis_node)]
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
#[cfg(linked_axis_node)]
use busbar_contract::abi::plane::{CLAIM_EXACT, CLAIM_OPEN, CLAIM_PATTERN};
#[cfg(linked_axis_node)]
use busbar_contract::auth::AuthPrincipal;
#[cfg(linked_axis_node)]
use busbar_contract::caps::{Pass, PrincipalId, Route};
#[cfg(linked_axis_node)]
use busbar_kernel::plane_driver::{
    Arrival, EgressFarEnd, FarEnd, FarPiece, OutboundRequest, Pick, UnitRoute,
};
#[cfg(linked_axis_node)]
use busbar_kernel::plane_routes::{PlaneReqCtx, PlaneRouteFuture, PlaneRouteSpec};

/// The egress class `dest.judge` applies when a plugin names none: the deployment's own stance.
pub const DEFAULT_EGRESS_CLASS: u32 = 0;

/// The kernel's host services, judging every destination by `dest`: the deployment's one
/// destination guard, the same judge the connector dials by (OWNER ruling DESTINATION GUARD).
#[must_use]
pub fn kernel_services(dest: Arc<dyn DestJudge>) -> KernelServices {
    KernelServices::new().with_dest_judge(dest)
}

/// THE COMPOSITION, once the configuration loads: the kernel's host services, judging by `dest`,
/// with the host's `records.secret` read over `credentials` (`root::credentials`: the App's
/// governance, through its swap handle once the App is built), are installed into the dispatcher's
/// [`LateServices`], before any plugin is bound, the kernel's own kept whole for the late attach and
/// the plane driver. A second call (a reload) installs nothing.
pub fn compose(
    dest: Arc<dyn DestJudge>,
    late: &LateServices,
    credentials: crate::root::credentials::AppCredentials,
) {
    let kernel = Arc::new(kernel_services(dest));
    let services = crate::root::credentials::CredentialServices::new(
        Arc::clone(&kernel) as Arc<dyn HostServices>,
        Arc::new(credentials),
    );
    if late.install_kernel(kernel, Arc::new(services)).is_err() {
        tracing::debug!("the kernel's host services were already installed");
    }
}

/// THE LATE ATTACH, once the first app is built (ARCHITECT S7-TICK 2026-10-01, ruling A): the
/// kernel's services gain what that build made. That is the runtime's blocking pool, bounded at the
/// record write queue's [`QUEUE_CAP`]; the governance signer, when governance is configured; and
/// the durable demotion record, its unprefixed rows belonging to the one plane that declares the
/// demotion record kind ([`demotion_owner`]); and the configured governance store `records` as the
/// record store. Each lives for the process (an apply reuses the
/// governance state and carries the demotion record), so each attaches once. With no kernel
/// services composed it attaches nothing. Runs on the runtime.
pub fn attach(
    late: &LateServices,
    records: Option<&busbar_kernel::governance::GovState>,
    signer: Option<Arc<dyn SignKey>>,
    demotions: &Arc<DemotionRecord>,
    planes: &[&PlaneDeclaration],
) {
    let Some(kernel) = late.kernel() else {
        return;
    };
    let pool = BlockingPool::new(tokio::runtime::Handle::current(), QUEUE_CAP);
    if kernel.attach_pool(Arc::new(pool)) {
        // THE WRITE-BEHIND CADENCE (ruling H2 U10, the root's half): the kernel's record flush
        // tick, once, for the services' life, beside the pool its flushes run on.
        let cadence = Arc::clone(&kernel);
        tokio::spawn(async move { cadence.flushes().await });
    }
    if let Some(signer) = signer {
        kernel.attach_signer(signer);
    }
    // THE RECORD STORE (ARCHITECT Q-L3B-RECORDS): the configured governance store, its typed records
    // and its plane-record slots, so a plane's record writes (a chained kind's journal among them)
    // persist where the deployment's state does.
    if let Some(gov) = records {
        if let Some(calls) = gov.store_calls() {
            kernel.attach_records(
                Arc::new(busbar_kernel::host_records::StoreRows(calls)),
                gov.store(),
            );
        }
    }
    if let Some(owner) = demotion_owner(planes) {
        kernel.attach_demotions(Arc::clone(demotions), owner);
    }
}

/// How long the graceful shutdown waits for the record write-behind to drain (ruling H2 U10: a hung
/// store holds no shutdown): five of the kernel's flush intervals.
pub const RECORD_DRAIN: std::time::Duration =
    std::time::Duration::from_secs(5 * busbar_kernel::host_records::FLUSH_INTERVAL.as_secs());

/// THE GRACEFUL SHUTDOWN'S RECORD DRAIN (ruling H2 U10, the root's half): every queued plane record
/// write is flushed before the store closes, waiting up to [`RECORD_DRAIN`]; off any runtime
/// worker (the drain blocks). `true` when all were written, or no kernel services are composed.
pub async fn drain_records(late: &LateServices) -> bool {
    let Some(kernel) = late.kernel() else {
        return true;
    };
    tokio::task::spawn_blocking(move || kernel.drain(RECORD_DRAIN))
        .await
        .unwrap_or(false)
}

/// The section key of the ONE plane that declares the demotion record kind: the plane whose
/// unprefixed demotion rows the kernel replays for its implicit first instance. `None` when no
/// plane, or more than one, declares it.
#[must_use]
pub fn demotion_owner(planes: &[&PlaneDeclaration]) -> Option<&'static str> {
    let mut owners = planes
        .iter()
        .filter(|d| declares_record_kind(d, KIND_DEMOTION));
    match (owners.next(), owners.next()) {
        (Some(d), None) => Some(d.config_section),
        _ => None,
    }
}

/// The kernel's host services, installed once after the configuration loads (see the module doc).
pub struct LateServices {
    installed: OnceLock<Arc<dyn HostServices>>,
    /// The kernel's own services, when those are what was composed ([`Self::install_kernel`]).
    kernel: OnceLock<Arc<KernelServices>>,
    /// The clock before the install: the kernel's own, judging no destination.
    clock: KernelServices,
}

/// Why [`LateServices::install`] would not take a second set of services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlreadyInstalled;

/// The reason every service answers before the kernel's are installed.
pub const NOT_INSTALLED: &str = "the kernel's host services are not installed yet";

impl LateServices {
    /// No services yet: every service answers REFUSED.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(LateServices {
            installed: OnceLock::new(),
            kernel: OnceLock::new(),
            clock: KernelServices::new(),
        })
    }

    /// Install the kernel's services. Once per process: a second install is refused and changes
    /// nothing, so a reload can never swap the services a running instance reaches.
    pub fn install(&self, services: Arc<dyn HostServices>) -> Result<(), AlreadyInstalled> {
        self.installed.set(services).map_err(|_| AlreadyInstalled)
    }

    /// Install `services` (the kernel's own, wrapped by the root's), as [`Self::install`] does, and
    /// keep `kernel` whole for the late attach ([`attach`]) and the plane driver ([`Self::kernel`]).
    pub fn install_kernel(
        &self,
        kernel: Arc<KernelServices>,
        services: Arc<dyn HostServices>,
    ) -> Result<(), AlreadyInstalled> {
        self.install(services)?;
        self.kernel.set(kernel).map_err(|_| AlreadyInstalled)
    }

    /// The kernel's composed services: the plane driver admits its instances and ticks over them.
    /// `None` before [`compose`].
    #[must_use]
    pub fn kernel(&self) -> Option<Arc<KernelServices>> {
        self.kernel.get().cloned()
    }

    /// Whether the kernel's services are installed.
    #[must_use]
    pub fn is_installed(&self) -> bool {
        self.installed.get().is_some()
    }

    /// The installed services, or the refusal every service answers before the install.
    fn served(&self) -> Result<&dyn HostServices, Stored> {
        self.installed
            .get()
            .map(|s| &**s)
            .ok_or_else(|| Stored::refused(NOT_INSTALLED))
    }
}

impl HostServices for LateServices {
    /// The kernel's clock once installed. `clock.now` has no refusal to answer, so before the
    /// install it is the kernel's own clock with no egress class, started with this value.
    fn now(&self) -> Reading {
        match self.installed.get() {
            Some(s) => s.now(),
            None => self.clock.now(),
        }
    }

    // Every other service is the installed services' answer, or REFUSED before the install.
    fn dest_judge(&self, dest: &str, class: u32, flags: u32, later: Option<Later>) -> Ran {
        match self.served() {
            Ok(s) => s.dest_judge(dest, class, flags, later),
            Err(r) => Ran::Now(r),
        }
    }

    fn records_get(&self, caller: &Caller, kind: &str, key: &[u8], later: Later) -> Ran {
        match self.served() {
            Ok(s) => s.records_get(caller, kind, key, later),
            Err(r) => Ran::Now(r),
        }
    }

    fn records_list(&self, caller: &Caller, list: RecordsList, later: Later) -> Ran {
        match self.served() {
            Ok(s) => s.records_list(caller, list, later),
            Err(r) => Ran::Now(r),
        }
    }

    fn records_claim(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        ttl_ms: u64,
        later: Later,
    ) -> Ran {
        match self.served() {
            Ok(s) => s.records_claim(caller, kind, key, ttl_ms, later),
            Err(r) => Ran::Now(r),
        }
    }

    fn sign(&self, caller: &Caller, data: &[u8]) -> Stored {
        match self.served() {
            Ok(s) => s.sign(caller, data),
            Err(r) => r,
        }
    }

    fn trust_sight(&self, caller: &Caller, counterparty: &str, hash: &str, later: Later) -> Ran {
        match self.served() {
            Ok(s) => s.trust_sight(caller, counterparty, hash, later),
            Err(r) => Ran::Now(r),
        }
    }

    fn trust_due(&self, caller: &Caller) -> Stored {
        match self.served() {
            Ok(s) => s.trust_due(caller),
            Err(r) => r,
        }
    }

    fn trust_verify(&self, caller: &Caller, cp: &str, payload: &[u8], sigs: &[u8]) -> Stored {
        match self.served() {
            Ok(s) => s.trust_verify(caller, cp, payload, sigs),
            Err(r) => r,
        }
    }

    fn entitlement_check(&self, caller: &Caller, unit: Option<u64>, target: &str) -> Stored {
        match self.served() {
            Ok(s) => s.entitlement_check(caller, unit, target),
            Err(r) => r,
        }
    }

    fn random_fill(&self, len: u64) -> Stored {
        match self.served() {
            Ok(s) => s.random_fill(len),
            Err(r) => r,
        }
    }

    fn records_secret(&self, kind: &str, id: &str, later: Later) -> Ran {
        match self.served() {
            Ok(s) => s.records_secret(kind, id, later),
            Err(r) => Ran::Now(r),
        }
    }

    fn unit_nest(&self, caller: &Caller, unit: Option<u64>, ask: NestAsk, later: Later) -> Ran {
        match self.served() {
            Ok(s) => s.unit_nest(caller, unit, ask, later),
            Err(r) => Ran::Now(r),
        }
    }

    fn work_open(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        kind: &str,
        record: &[u8],
        later: Later,
    ) -> Ran {
        match self.served() {
            Ok(s) => s.work_open(caller, unit, kind, record, later),
            Err(r) => Ran::Now(r),
        }
    }

    fn work_find(&self, caller: &Caller, unit: Option<u64>, reference: &[u8], later: Later) -> Ran {
        match self.served() {
            Ok(s) => s.work_find(caller, unit, reference, later),
            Err(r) => Ran::Now(r),
        }
    }

    fn work_settle(&self, caller: &Caller, handle: u64, record: &[u8], later: Later) -> Ran {
        match self.served() {
            Ok(s) => s.work_settle(caller, handle, record, later),
            Err(r) => Ran::Now(r),
        }
    }

    fn work_resume(&self, caller: &Caller, unit: Option<u64>, handle: u64, later: Later) -> Ran {
        match self.served() {
            Ok(s) => s.work_resume(caller, unit, handle, later),
            Err(r) => Ran::Now(r),
        }
    }

    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran {
        match self.served() {
            Ok(s) => s.disk_append(dest, bytes, later),
            Err(r) => Ran::Now(r),
        }
    }
}

// ── the door planes, composed ─────────────────────────────────────────────────────────────────────

/// ONE DOOR PLANE, COMPOSED (TODO U6-U7, ARCHITECT Q-SW4 2026-10-02): its instance, the driver the
/// kernel serves it through, the snapshot its `open` published (its claims and admin routes), and
/// what its units are served by: its tail's facts, the pools its section states, its money steps
/// and its egress.
pub struct ServedPlane {
    /// The instance's label.
    pub instance: String,
    /// The plane's driver: admitted to the kernel's services, its driver ticket minted.
    pub driver: Arc<PlaneDriver>,
    /// The first generation's snapshot, as the host copied it.
    pub snapshot: OwnedSnapshot,
    /// The `audit_kind` its tail states: what its units are audited under.
    pub audit_kind: &'static str,
    /// Its key, scope kind, billable classes and fee units, read off its tail.
    pub facts: DoorFacts,
    /// Its money steps: the same seam its driver reports units, cancel bills and abandoned ends to.
    pub money: Arc<PlaneMoney>,
    /// What its units are served over for the current refresh generation (its pools and its
    /// egress), replaced whole by a config apply ([`DoorApply`]).
    pub live: Arc<DoorApply>,
    /// The kernel's host services it was admitted to: its units' records are written there.
    pub kernel: Arc<KernelServices>,
    /// Its tail's dialects, in order: what a unit's dialect index names.
    pub dialects: Vec<&'static str>,
}

/// WHAT ONE GENERATION OF A DOOR PLANE IS SERVED OVER: its section as written, its refresh
/// generation, the pools and entries the section states (ARCHITECT Q-SW6), and its egress sealed
/// for the section's members (the kernel's walk over the connector; `None` = none composed, every
/// walk of its units is exhausted at once and nothing is dialled).
pub struct DoorLive {
    /// The section, as written.
    pub section: serde_yaml::Value,
    /// The plane's generation serving it.
    pub generation: u64,
    /// Its pools and entries.
    pub pools: DoorPools,
    /// Its egress.
    pub egress: Option<Arc<Egress>>,
    /// The tail's facts as this generation states them (with the generation's provider dialects,
    /// for the translation counter).
    pub facts: DoorFacts,
    /// The health-probe service's target for this generation (K7), when the plane answers probes
    /// and a member probes: held here, so a replaced generation's probers exit at their next tick.
    pub probes: Option<Arc<busbar_kernel::plane_driver::PlaneProbes>>,
    /// What the ranking hooks are shown of the model-serving pools' members beside the walk: their
    /// meta and their live standing (`None` for a plane whose egress is the generic walk).
    pub shown: Option<crate::root::model_egress::ModelShown>,
}

/// What a door plane's egress is re-sealed over on a config apply: the providers the deployment
/// booted with, the auth plugins, the connector and the journal.
pub struct ApplyReach {
    providers: BTreeMap<String, crate::root::door_steps::ProviderRoute>,
    auths: Arc<crate::root::door_steps::OutboundAuths>,
    conns: Arc<dyn busbar_contract::conn::PollConns>,
    journal: Arc<dyn busbar_kernel_egress::ports::Journal>,
    stream_ceiling_secs: u64,
    upgrades: Vec<&'static str>,
}

/// A CONFIG APPLY ON ONE SERVED DOOR PLANE (ARCHITECT Q-DEL-A2A-APPLY; THE DESIGN §11, plugin
/// memory is "valid to its next refresh generation"): every apply refreshes the plane onto a new
/// generation of the section the installed generation writes, so the plane re-reads it and its
/// generation-scoped memory resets with it, as predev rebuilt the plane on every apply; its pools
/// and egress are re-derived from that section. The generation before the previous one is retired
/// (units still running on the previous one finish on it).
pub struct DoorApply {
    plugin: DoorPlane,
    served_facts: crate::root::loader::dispatch::kinds::plane::ServedFacts,
    facts: DoorFacts,
    reach: Option<ApplyReach>,
    live: std::sync::RwLock<Arc<DoorLive>>,
    /// The plane's driver, which a generation's health probes run their units on (K7).
    driver: Arc<PlaneDriver>,
    /// The health-probe schedule its generations share, phase-stable across a config apply that
    /// keeps the lane table it is indexed by, and that lane table.
    probes: std::sync::Mutex<(LaneTable, Arc<busbar_kernel::probe::ProbeSchedule>)>,
    /// The scope kinds its Statement declares.
    scope_kinds: Vec<&'static str>,
}

/// The lane table a probe schedule's deadlines are indexed by
/// ([`crate::root::model_egress::ModelServing::lane_table`]).
type LaneTable = Vec<(usize, String, String)>;

impl DoorApply {
    /// THE PROBE SCHEDULE A GENERATION SEALED OVER `models` RUNS ON (1.5.5 `build`, v1.5.5
    /// main.rs:3596-3606): the current one, carried, when its lane table is the same; else a fresh
    /// one, since its deadlines are kept by lane index and another table puts another member at an
    /// index.
    fn schedule_for(
        &self,
        models: Option<&crate::root::model_egress::ModelServing>,
    ) -> (LaneTable, Arc<busbar_kernel::probe::ProbeSchedule>) {
        let table = models.map_or_else(
            Vec::new,
            crate::root::model_egress::ModelServing::lane_table,
        );
        let held = self
            .probes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if held.0 == table {
            return (table, Arc::clone(&held.1));
        }
        let lanes = models.map_or(0, |m| m.probe_members().0);
        (
            table,
            Arc::new(busbar_kernel::probe::ProbeSchedule::new(lanes)),
        )
    }

    /// The current generation's pools and egress.
    #[must_use]
    pub fn current(&self) -> Arc<DoorLive> {
        Arc::clone(
            &self
                .live
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Refresh onto the generation `app` installed: its section (the plane's slot in it, else the
    /// section the plane serves now), a new refresh generation, and pools and egress re-derived.
    /// A plane that will not refresh keeps serving its current generation, logged.
    pub fn apply(&self, app: &busbar_kernel::state::App) {
        // The plane serving the kernel-owned `pools` map reads the deployment's top-level sections,
        // not a slot of its own: it is refreshed from the generation's configuration projection
        // ([`DoorAppliers::refresh_models`]).
        if self.served_facts.section == busbar_contract::section::RESERVED_POOLS_KEY {
            return;
        }
        let now = self.current();
        let section = app
            .plane_slots
            .get(self.facts.plane.as_str())
            .and_then(|s| s.downcast_ref::<busbar_kernel::plane::door::DoorSlot>())
            .map_or_else(|| now.section.clone(), |s| s.section.value.clone());
        match self.refreshed(&section, now.generation + 1, &*app.secret_resolver) {
            Ok(next) => {
                *self
                    .live
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(next);
                if now.generation > 1 {
                    crate::root::loader::dispatch::kinds::plane::retire_door(
                        &self.plugin,
                        now.generation - 1,
                    );
                }
            }
            Err(e) => tracing::warn!(
                plane = self.facts.plane.as_str(),
                error = %e,
                "door plane kept its generation across a config apply"
            ),
        }
    }

    fn refreshed(
        &self,
        section: &serde_yaml::Value,
        generation: u64,
        secrets: &dyn busbar_contract::secret::SecretResolve,
    ) -> Result<DoorLive, String> {
        let settings = if section.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(section).map_err(|e| format!("its section: {e}"))?
        };
        crate::root::loader::dispatch::kinds::plane::refresh_door(
            &self.plugin,
            &settings,
            generation,
        )?;
        let pools = DoorPools::of(section);
        let egress = match &self.reach {
            Some(r) => {
                let reach = crate::root::door_steps::DoorReach {
                    providers: &r.providers,
                    secrets,
                    auths: Arc::clone(&r.auths),
                    conns: Arc::clone(&r.conns),
                    stream_ceiling_secs: r.stream_ceiling_secs,
                    upgrades: r.upgrades.clone(),
                    models: None,
                };
                let routes = crate::root::door_steps::member_routes(
                    section,
                    &pools,
                    &self.served_facts,
                    &reach,
                )?;
                Some(Arc::new(crate::root::door_steps::compose_egress(
                    &self.facts,
                    &pools,
                    self.plugin.instance(),
                    Arc::clone(&r.conns),
                    &routes,
                    Arc::clone(&r.journal),
                    r.stream_ceiling_secs,
                )?))
            }
            None => None,
        };
        Ok(DoorLive {
            section: section.clone(),
            generation,
            pools,
            egress,
            facts: self.facts.clone(),
            probes: None,
            shown: None,
        })
    }
}

/// EVERY SERVED DOOR PLANE'S APPLY, kept when the planes move into the data routes, for the
/// handle's appliers ([`busbar_kernel::state::AppHandle::on_apply`]).
#[derive(Clone, Default)]
pub struct DoorAppliers(Vec<Arc<DoorApply>>);

impl DoorAppliers {
    /// Refresh every served door plane onto the generation `app` installed.
    pub fn apply(&self, app: &busbar_kernel::state::App) {
        for plane in &self.0 {
            plane.apply(app);
        }
    }

    /// A CONFIG APPLY, as the plane serving the kernel-owned `pools` map takes it (spec Part 1
    /// line 569: one validated object per `refresh`): refreshed onto the next generation with the
    /// new configuration's sections, and the generation its units are served by sealed anew over the
    /// new providers and pool bounds and swapped in; a unit already running keeps the generation it
    /// started on, as 1.5.5's request kept the snapshot it arrived on. The generation before the
    /// previous one is retired. A plane that will not refresh or seal keeps serving its previous
    /// generation, and says why.
    pub fn refresh_models(
        &self,
        sections: &BTreeMap<&'static str, serde_yaml::Value>,
        egress: &DoorEgress<'_>,
    ) {
        for p in &self.0 {
            let facts = &p.served_facts;
            if facts.section != busbar_contract::section::RESERVED_POOLS_KEY {
                continue;
            }
            let Some(section) = sections.get(facts.section) else {
                continue;
            };
            let name = p.plugin.name();
            let settings = match serde_json::to_vec(&settings_of(facts, section, sections)) {
                Ok(settings) => settings,
                Err(e) => {
                    tracing::error!(plane = name, error = %e, "door plane's new configuration is not JSON; it keeps serving the previous one");
                    continue;
                }
            };
            let walked = walked_section(facts, section, sections);
            let now = p.current();
            let next = now.generation + 1;
            if let Err(e) = crate::root::loader::dispatch::kinds::plane::refresh_door(
                &p.plugin, &settings, next,
            ) {
                tracing::error!(plane = name, error = %e, "door plane did not refresh onto the new configuration; it keeps serving the previous one");
                continue;
            }
            match seal_live(
                name,
                &p.plugin,
                facts,
                &p.scope_kinds,
                &walked,
                Some(egress),
                next,
                p.facts.bench_below_trip_threshold,
            ) {
                Ok(mut live) => {
                    let (table, schedule) = p.schedule_for(egress.reach.models);
                    arm_probes(&p.driver, facts, &mut live, Some(egress), &schedule);
                    *p.probes
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = (table, schedule);
                    *p.live
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(live);
                }
                Err(e) => {
                    tracing::error!(plane = name, error = %e, "door plane's new configuration did not seal; it keeps serving the previous one");
                    continue;
                }
            }
            if now.generation > 1 {
                crate::root::loader::dispatch::kinds::plane::retire_door(
                    &p.plugin,
                    now.generation - 1,
                );
            }
        }
    }
}

impl std::fmt::Debug for DoorLive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorLive")
            .field("generation", &self.generation)
            .field("pools", &self.pools)
            .field("egress", &self.egress.is_some())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for DoorApply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorApply")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ServedPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServedPlane")
            .field("instance", &self.instance)
            .field("snapshot", &self.snapshot)
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

/// EVERY DOOR PLANE THIS PROCESS SERVES, composed once after the first app is built.
#[derive(Debug, Default)]
pub struct Served {
    /// In the order the planes were bound.
    pub planes: Vec<ServedPlane>,
    /// The posting site the planes' money steps post an abandoned end to, and the units' facts are
    /// opened on while they run: the process's one node's.
    #[cfg(linked_axis_node)]
    pub post: Option<Arc<crate::root::plane_node::NodeEndPost>>,
    /// The framer that answers a claim, by its name: what frames a stream that arrived on a claim
    /// another framer than the data listener's own answers (ARCHITECT 4l). `None` = the process's
    /// one connector's.
    pub framers: Option<StreamFramers>,
}

/// The framer that answers a claim, by its name (`Connector::framer_for`).
#[derive(Clone)]
pub struct StreamFramers(pub Arc<FramerFor>);

/// A lookup of the framer that answers a claim, by its name.
pub type FramerFor =
    dyn Fn(&str) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>> + Send + Sync;

impl std::fmt::Debug for StreamFramers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamFramers")
    }
}

impl Served {
    /// Every served plane's config apply, kept for the handle's appliers once the planes move into
    /// the data routes.
    #[must_use]
    pub fn appliers(&self) -> DoorAppliers {
        DoorAppliers(self.planes.iter().map(|p| Arc::clone(&p.live)).collect())
    }
}

impl Served {
    /// Each plane's tick schedule and its ready-session fan-out (`drive`'s names, R-B), on its
    /// driver ticket, spawned on the current runtime: a unit served as a duplex session (K6) is
    /// woken through them for the output it owes on the tick (ARCHITECT round 5 Q-L3B-K6-HTTP (a)).
    pub fn spawn_ticks(&self) {
        for p in &self.planes {
            let driver = Arc::clone(&p.driver);
            tokio::spawn(async move { driver.ticks().await });
            let driver = Arc::clone(&p.driver);
            tokio::spawn(async move { driver.drives().await });
        }
    }
}

/// THE DOOR PLANES, COMPOSED ([`compose_planes`], TODO U6-U7) over the deployment's governance book
/// `gov`: each plane bound through its door whose section this deployment writes is opened, driven
/// and ticked once, its money posted onto the process's one node. A deployment without governance
/// has no money book for a driven unit to settle on, so its door planes stay bound and unopened.
///
/// # Errors
///
/// A configured plane that will not compose ([`compose_planes`]), or, in a build that links no
/// node to post a unit's money on, any configured door plane at all, which the boot refuses rather
/// than leaving its claims unserved.
#[allow(clippy::too_many_arguments)]
pub fn compose_served(
    gov: Option<Arc<busbar_kernel::governance::GovState>>,
    doors: &[(String, DoorPlane)],
    dispatcher: &Arc<Dispatcher>,
    late: &LateServices,
    sections: &BTreeMap<&'static str, serde_yaml::Value>,
    public_url: Option<&str>,
    reach: &crate::root::door_steps::DoorReach<'_>,
    host: Option<busbar_kernel::plane_driver::GenerationHost>,
) -> Result<Served, String> {
    let Some(gov) = gov else {
        if !doors.is_empty() {
            tracing::warn!("door planes stay unopened: no governance book to settle on");
        }
        return Ok(Served::default());
    };
    #[cfg(linked_axis_node)]
    {
        let post = Arc::new(crate::root::plane_node::NodeEndPost::new(
            crate::root::plane_node::node(),
        ));
        let stage = host.map(|host| HookStage {
            host,
            gov: Arc::clone(&gov),
        });
        let site = Arc::clone(&post);
        let money = move || {
            Arc::new(PlaneMoney::new(
                Arc::clone(&gov),
                Arc::clone(&site) as Arc<dyn busbar_kernel::plane_driver::EndPost>,
            ))
        };
        let egress = DoorEgress {
            reach,
            journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
        };
        let mut served = compose_planes(
            doors,
            dispatcher,
            late,
            sections,
            public_url,
            &money,
            Some(&egress),
            stage.as_ref(),
        )?;
        served.post = Some(post);
        Ok(served)
    }
    #[cfg(not(linked_axis_node))]
    {
        let _ = (gov, dispatcher, late, reach, public_url, host);
        match doors
            .iter()
            .find(|(_, plugin)| sections.contains_key(plugin.served().section))
        {
            Some((instance, _)) => Err(format!(
                "{instance}: a door plane's money is posted on the process's node, and this build \
                 links none"
            )),
            None => Ok(Served::default()),
        }
    }
}

/// THE KERNEL'S HOOK STAGE as a door plane's units bind it: the current generation's engine host
/// (its hook registry), read per unit so a config apply reaches the next unit, and the governance
/// state a verified principal's key is read from.
pub struct HookStage {
    /// The current generation's engine host.
    pub host: busbar_kernel::plane_driver::GenerationHost,
    /// The governance state.
    pub gov: Arc<busbar_kernel::governance::GovState>,
}

impl HookStage {
    /// The binder for a plane whose tail states `dialects`.
    fn binder(&self, dialects: &[&str]) -> Arc<dyn busbar_kernel::plane_driver::HookBinder> {
        let gov = Arc::clone(&self.gov);
        Arc::new(busbar_kernel::plane_driver::HostHooks {
            host: Arc::clone(&self.host),
            caller: Arc::new(busbar_kernel::plane_driver::EngineCaller {
                host: Arc::clone(&self.host),
                keys: Arc::new(move |principal: &str| gov.lookup_by_sub(principal)),
            }),
            dialects: dialects.iter().map(|d| (*d).to_string()).collect(),
        })
    }

    /// The GATE-FIRST binder of the plane registered under `plane_key` (its tail states
    /// `abi::plane::TAIL_HOOKS_GATED`): the gates and rewrites the deployment attached to the
    /// entry the plane's projection names, filed under the plane's registry key.
    fn gated(&self, plane_key: &str) -> Arc<dyn busbar_kernel::plane_driver::HookBinder> {
        let gov = Arc::clone(&self.gov);
        Arc::new(busbar_kernel::plane_driver::HostGatedHooks {
            host: Arc::clone(&self.host),
            plane_key: plane_key.to_string(),
            keys: Arc::new(move |principal: &str| gov.lookup_by_sub(principal)),
        })
    }
}

/// THE DOOR PLANES' SECTIONS WITH THEIR POOLS: each section `pools` names (by its key) carries, at
/// its reserved `pools` key, the unified pools its members resolved to (each with its `members` and
/// its `repeatable` operations), so its DoorPools walks them and its plane names them (ARCHITECT
/// round 4 Q-L3B-SURFACES (h)). A section with no pools, or one this document does not write, is
/// left as it is.
#[must_use]
pub fn with_pools(
    mut sections: BTreeMap<&'static str, serde_yaml::Value>,
    pools: &[(
        &'static str,
        BTreeMap<String, busbar_kernel::failover::CandidatePoolCfg>,
    )],
) -> BTreeMap<&'static str, serde_yaml::Value> {
    use busbar_contract::section::{
        POOL_MEMBERS_KEY, POOL_MEMBER_GRANTED_KEY, POOL_REPEATABLE_KEY, RESERVED_POOLS_KEY,
    };
    for (key, stated) in pools {
        if stated.is_empty() {
            continue;
        }
        let Some(serde_yaml::Value::Mapping(section)) = sections.get_mut(key) else {
            continue;
        };
        let mut map = serde_yaml::Mapping::new();
        for (name, pool) in stated {
            let mut entry = serde_yaml::Mapping::new();
            entry.insert(
                POOL_MEMBERS_KEY.into(),
                serde_yaml::Value::Sequence(
                    pool.members.iter().map(|m| m.as_str().into()).collect(),
                ),
            );
            entry.insert(
                POOL_REPEATABLE_KEY.into(),
                serde_yaml::Value::Sequence(
                    pool.repeatable.iter().map(|m| m.as_str().into()).collect(),
                ),
            );
            entry.insert(
                POOL_MEMBER_GRANTED_KEY.into(),
                serde_yaml::Value::Bool(true),
            );
            map.insert(name.as_str().into(), serde_yaml::Value::Mapping(entry));
        }
        section.insert(RESERVED_POOLS_KEY.into(), serde_yaml::Value::Mapping(map));
    }
    sections
}

/// WHAT A DOOR PLANE'S EGRESS IS SEALED OVER: how its members are reached ([`DoorReach`]) and the
/// journal its walk's dispatch records are written to (the node's end post, ARCHITECT P3 (c)).
pub struct DoorEgress<'a> {
    /// The process's reach.
    pub reach: &'a crate::root::door_steps::DoorReach<'a>,
    /// The write-ahead dispatch record.
    pub journal: Arc<dyn busbar_kernel_egress::ports::Journal>,
}

/// THE DOOR PLANES' COMPOSITION (ARCHITECT Q-SW4, 2026-10-02): every plane bound through its door
/// (`root::boot::door_planes`) whose declared section this deployment writes (LAW 7: a plugin
/// loads iff its section is present) is opened with that section as its settings, and composed:
/// a [`PlaneInstance`] on `dispatcher` (unit tickets on worker 0, where its driver ticket is
/// minted), a [`PlaneDriver`] admitted to the kernel's composed services with the plane's tail
/// facts and the money steps `money` builds for it, the pools its section states, and its admin
/// routes published on the admin router's table (`plane_driver::serve`, K-SERVE). A plane whose
/// section is absent stays bound and unopened, as before. With `egress`, each plane's egress is
/// sealed over it ([`crate::root::door_steps::member_routes`]); without, none is (every walk is
/// exhausted at once). The data routes are the data router's construction ([`data_routes`]).
///
/// # Errors
///
/// A plane that will not open, publish a snapshot, be admitted, publish its admin routes or seal
/// its members' routes, named: the boot refuses it, as it refuses a plane that will not bind.
#[allow(clippy::too_many_arguments)]
pub fn compose_planes(
    doors: &[(String, DoorPlane)],
    dispatcher: &Arc<Dispatcher>,
    late: &LateServices,
    sections: &BTreeMap<&'static str, serde_yaml::Value>,
    public_url: Option<&str>,
    money: &dyn Fn() -> Arc<PlaneMoney>,
    egress: Option<&DoorEgress<'_>>,
    hooks: Option<&HookStage>,
) -> Result<Served, String> {
    compose_planes_over(
        &crate::LINKED,
        doors,
        dispatcher,
        late,
        sections,
        public_url,
        money,
        egress,
        hooks,
    )
}

/// [`compose_planes`] over `linked`, the linked table each door plane's declared facts are read
/// from beside the dropped-in manifests (its breaker fact, [`crate::root::linked::door_breaker`]).
///
/// # Errors
///
/// As [`compose_planes`]; and a door plane whose declared facts do not read.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compose_planes_over(
    linked: &crate::root::linked::Linked,
    doors: &[(String, DoorPlane)],
    dispatcher: &Arc<Dispatcher>,
    late: &LateServices,
    sections: &BTreeMap<&'static str, serde_yaml::Value>,
    public_url: Option<&str>,
    money: &dyn Fn() -> Arc<PlaneMoney>,
    egress: Option<&DoorEgress<'_>>,
    hooks: Option<&HookStage>,
) -> Result<Served, String> {
    let mut served = Served::default();
    if doors.is_empty() {
        return Ok(served);
    }
    let kernel = late
        .kernel()
        .ok_or("the kernel's host services are not composed")?;
    for (instance, plugin) in doors {
        let served_facts = plugin.served();
        let Some(section) = sections.get(served_facts.section) else {
            tracing::debug!(
                instance,
                section = served_facts.section,
                "door plane not configured"
            );
            continue;
        };
        // A MODEL-SERVING PLANE in the previous release's layout is handed the `pools` map and each
        // section it reads beside it, keyed; its walk is the uniform model-serving section over its
        // `pools:` and the top-level `models:` (#49).
        let settings = settings_of(&served_facts, section, sections);
        let walked = walked_section(&served_facts, section, sections);
        // The plane's other owned sections this document writes, as written, by section name: it
        // reads them beside its settings (ARCHITECT Q-L3B-AUD). Names come from its Statement.
        let owned: serde_json::Map<String, serde_json::Value> = served_facts
            .owns
            .iter()
            .filter_map(|name| {
                let value = serde_json::to_value(sections.get(name)?).ok()?;
                Some(((*name).to_string(), value))
            })
            .collect();
        let snapshot =
            open(plugin, &settings, public_url, &owned).map_err(|e| format!("{instance}: {e}"))?;
        let section = &walked;
        let calls = Arc::new(PlaneInstance::new(
            plugin.clone(),
            Arc::clone(dispatcher),
            0,
        ));
        let plane_money = money();
        let config = DriverConfig {
            caps: BufferCaps::default(),
            op_classes: served_facts
                .op_classes
                .iter()
                .map(|c| OpClassId::new(c))
                .collect(),
            status_of: refusal_status,
            refusal_statuses: calls.refusal_statuses(),
            // Each unit is lent its caller's opaque reference under the book's signing material,
            // as a plane that attributes its work to a caller (a task's owner) is lent it.
            caller_refs: plane_money.caller_refs(),
        };
        let caller = Caller {
            instance: Arc::from(instance.as_str()),
            plugin: Arc::from(plugin.name()),
            kind: KindCode::Plane,
        };
        let driver = PlaneDriver::new(
            Arc::clone(&calls) as Arc<dyn PlaneCalls>,
            config,
            Arc::clone(&plane_money) as Arc<dyn MoneySeam>,
            Arc::clone(&kernel),
            (served_facts.section, section),
        )
        .map_err(|e| format!("{instance}: {e}"))?
        .with_records(Arc::clone(&kernel), caller.clone());
        // THE HOOK STAGE IN THE PLANE'S OWN ORDER (spec Part 3 section 12 "Hooks": the hook stages
        // run at the head of the route leg, in the hook order 1.5.5 used for that plane): a plane
        // whose tail states the gate-first order has its entries' gates and rewrites bound, filed
        // under its registry key; the plane that serves the `pools` map, the one 1.5.5 ran its
        // request hooks on, binds the kernel's hooks in that order (ARCHITECT K5).
        let driver = match hooks {
            Some(stage)
                if served_facts.tail_flags & busbar_contract::abi::plane::TAIL_HOOKS_GATED != 0 =>
            {
                driver.with_hooks(stage.gated(plugin.name()))
            }
            Some(stage) if served_facts.section == busbar_contract::section::RESERVED_POOLS_KEY => {
                driver.with_hooks(stage.binder(&served_facts.dialects))
            }
            _ => driver,
        };
        let routes = snapshot
            .admin_routes
            .iter()
            .map(|r| ServeRoute {
                verb: r.verb.clone(),
                target: r.target.clone(),
                flags: r.flags,
                audit_verb: r.audit_verb.clone(),
                style: r.style.clone(),
            })
            .collect();
        // The admin router's fallback is this table, so a kernel admin route always matches first
        // and is never shadowed; no route is reserved beyond that.
        publish(
            ServeTable {
                instance: instance.clone(),
                audit_kind: served_facts.audit_kind.to_string(),
                calls,
                caps: BufferCaps::default(),
                routes,
                records: Some((Arc::clone(&kernel), caller)),
            },
            &[],
        )
        .map_err(|c| format!("{instance}: admin route {:?} overlaps {}", c.route, c.with))?;
        let declared = plugin.declared();
        // EVERY REPORTED CLASS IS REGISTERED (THE DESIGN §7): the classes a plane may report are the
        // ones its tail declares, linked or dropped in, registered once at its composition, so its
        // units' lines resolve them.
        let mut registration = crate::root::kernel::new_registration();
        for class in served_facts
            .billable_classes
            .iter()
            .chain(&served_facts.fee_units)
        {
            if registration.key(class).is_none() {
                return Err(format!(
                    "{instance}: its class '{class}' cannot join the image's vocabulary"
                ));
            }
        }
        // THE PLANE'S BREAKER FACT, as it declares it (ARCHITECT Q4): read off its `declares`
        // section, whichever plane it is; absent, its members' cells keep the default.
        let bench = crate::root::linked::door_breaker(
            linked,
            crate::root::linked::dropped(),
            plugin.name(),
        )
        .map_err(|e| format!("{instance}: {e}"))?
        .map(|b| b.bench_below_trip_threshold);
        let mut live = seal_live(
            instance,
            plugin,
            &served_facts,
            &declared.scope_kinds,
            section,
            egress,
            1,
            bench,
        )?;
        // The door's own requests to its members carry the members' bindings (ARCHITECT round 5
        // Q-L3B-DOOR-EXCHANGE), held on the connection table its need is declared on.
        if let (Some(egress), Some(table)) = (egress, plugin.conn_table()) {
            let pools = DoorPools::of(section);
            let routes = crate::root::door_steps::member_routes(
                section,
                &pools,
                &served_facts,
                egress.reach,
            )
            .map_err(|e| format!("{instance}: {e}"))?;
            crate::root::door_steps::bind_member_fetches(
                &served_facts,
                &routes,
                plugin.instance(),
                &*table,
                kernel.units(),
            );
        }
        let driver = Arc::new(driver);
        let models = egress.and_then(|e| e.reach.models);
        let lane_table = models.map_or_else(
            Vec::new,
            crate::root::model_egress::ModelServing::lane_table,
        );
        let probe_schedule = Arc::new(busbar_kernel::probe::ProbeSchedule::new(
            models.map_or(0, |m| m.probe_members().0),
        ));
        arm_probes(&driver, &served_facts, &mut live, egress, &probe_schedule);
        let facts = live.facts.clone();
        let reach = egress.map(|e| ApplyReach {
            providers: e.reach.providers.clone(),
            auths: Arc::clone(&e.reach.auths),
            conns: Arc::clone(&e.reach.conns),
            journal: Arc::clone(&e.journal),
            stream_ceiling_secs: e.reach.stream_ceiling_secs,
            upgrades: e.reach.upgrades.clone(),
        });
        let live = Arc::new(DoorApply {
            plugin: plugin.clone(),
            served_facts: served_facts.clone(),
            facts: facts.clone(),
            reach,
            live: std::sync::RwLock::new(Arc::new(live)),
            driver: Arc::clone(&driver),
            probes: std::sync::Mutex::new((lane_table, probe_schedule)),
            scope_kinds: declared.scope_kinds.clone(),
        });
        served.planes.push(ServedPlane {
            instance: instance.clone(),
            driver,
            snapshot,
            audit_kind: served_facts.audit_kind,
            facts,
            money: plane_money,
            live,
            kernel: Arc::clone(&kernel),
            dialects: served_facts.dialects.clone(),
        });
    }
    Ok(served)
}

/// THE GENERATION A DOOR PLANE'S UNITS ARE SERVED BY ([`DoorLive`], refresh generation `generation`), sealed over its walked
/// `section`: the tail's facts (the flat card's empty plane key for the plane serving the `pools`
/// map, which owns 1.5.5's `rate_card:`; each provider's dialect, for the translation counter), the
/// section's pools and, with `egress`, each member's route resolved and its credential bound by the
/// auth plugin serving its style over the connector its needs were declared on (THE DESIGN §6 steps
/// 2-3), the plane serving the `pools` map walking its pools with the previous release's semantics
/// on the kernel's own breaker cells ([`crate::root::model_egress`]).
///
/// # Errors
///
/// A member whose route or credential binding cannot be resolved, named.
#[allow(clippy::too_many_arguments)]
fn seal_live(
    instance: &str,
    plugin: &DoorPlane,
    served_facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    scope_kinds: &[&str],
    section: &serde_yaml::Value,
    egress: Option<&DoorEgress<'_>>,
    generation: u64,
    bench_below_trip_threshold: Option<bool>,
) -> Result<DoorLive, String> {
    let models_plane = served_facts.section == busbar_contract::section::RESERVED_POOLS_KEY;
    let card_plane = if models_plane { "" } else { plugin.name() };
    let mut facts = door_facts(
        card_plane,
        scope_kinds,
        &served_facts.billable_classes,
        &served_facts.fee_units,
        served_facts.audit_kind,
        served_facts
            .keeps
            .iter()
            .map(|k| busbar_kernel::plane_driver::ResponseKeep {
                mode: k.mode,
                kept: k.kept.iter().map(|n| (*n).to_string()).collect(),
                denied: k.denied.iter().map(|n| (*n).to_string()).collect(),
            })
            .collect(),
    );
    facts.bench_below_trip_threshold = bench_below_trip_threshold;
    if let Some(egress) = egress {
        facts.translations = (
            served_facts
                .dialects
                .iter()
                .map(|d| (*d).to_string())
                .collect(),
            Arc::new(
                egress
                    .reach
                    .providers
                    .iter()
                    .map(|(name, p)| (name.clone(), p.protocol.clone()))
                    .collect(),
            ),
        );
    }
    let pools = DoorPools::of(section);
    let egress = match egress {
        Some(egress) => {
            let routes =
                crate::root::door_steps::member_routes(section, &pools, served_facts, egress.reach)
                    .map_err(|e| format!("{instance}: {e}"))?;
            let sealed = match egress.reach.models {
                Some(models) if models_plane => crate::root::model_egress::compose(
                    &facts,
                    models,
                    plugin.instance(),
                    Arc::clone(&egress.reach.conns),
                    &routes,
                    Arc::clone(&egress.journal),
                    egress.reach.stream_ceiling_secs,
                )
                .map(|(e, shown)| (e, Some(shown))),
                _ => crate::root::door_steps::compose_egress(
                    &facts,
                    &pools,
                    plugin.instance(),
                    Arc::clone(&egress.reach.conns),
                    &routes,
                    Arc::clone(&egress.journal),
                    egress.reach.stream_ceiling_secs,
                )
                .map(|e| (e, None)),
            };
            let (sealed, shown) = sealed.map_err(|e| format!("{instance}: {e}"))?;
            Some((Arc::new(sealed), shown))
        }
        None => None,
    };
    let (egress, shown) = match egress {
        Some((e, shown)) => (Some(e), shown),
        None => (None, None),
    };
    Ok(DoorLive {
        section: section.clone(),
        generation,
        pools,
        egress,
        facts,
        probes: None,
        shown,
    })
}

/// THE HEALTH PROBES OF ONE GENERATION (K7; 1.5.5 `health:` per provider, `none | dead | active`):
/// for the plane serving the `pools` map whose tail states `TAIL_PROBES`, a probe target over
/// `live`'s sealed egress and `driver`, its probers spawned as a new generation of `schedule` (the
/// previous generation's exit at their next tick). A build without the node has no kernel to run
/// a probe unit on and probes nothing.
fn arm_probes(
    driver: &Arc<PlaneDriver>,
    served_facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    live: &mut DoorLive,
    egress: Option<&DoorEgress<'_>>,
    schedule: &Arc<busbar_kernel::probe::ProbeSchedule>,
) {
    #[cfg(linked_axis_node)]
    {
        let (Some(sealed), Some(models)) = (&live.egress, egress.and_then(|e| e.reach.models))
        else {
            return;
        };
        if served_facts.section != busbar_contract::section::RESERVED_POOLS_KEY {
            return;
        }
        let (lanes, members) = models.probe_members();
        if members.is_empty() {
            return;
        }
        let (kernel, keys) = crate::root::plane_node::node().kernel_and_keys();
        let Some(target) = busbar_kernel::plane_driver::PlaneProbes::new(
            if served_facts.probes {
                busbar_contract::abi::plane::TAIL_PROBES
            } else {
                0
            },
            Arc::clone(driver),
            Arc::clone(sealed),
            kernel,
            keys,
            (0..lanes)
                .map(|i| busbar_contract::DestinationId::new(i as u64))
                .collect(),
        ) else {
            return;
        };
        let target = Arc::new(target);
        let members: Vec<busbar_kernel::probe::ProbeMember> =
            members.into_iter().map(|(_, m)| m).collect();
        busbar_kernel::probe::spawn_probers(&target, schedule, &members);
        live.probes = Some(target);
    }
    #[cfg(not(linked_axis_node))]
    let _ = (driver, served_facts, live, egress, schedule);
}

/// THE SETTINGS A DOOR PLANE OPENS WITH (spec Part 1 §4: one validated JSON object `{section:
/// value}`): a plane that declares the kernel-owned `pools` map (the previous release's top-level
/// model-serving layout) is handed it and each section it reads beside it (`SECTION_CONSUMED`)
/// that this deployment writes, keyed; a plane that declares a section of its own is handed that
/// section, as its door reads it.
fn settings_of(
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    section: &serde_yaml::Value,
    sections: &BTreeMap<&'static str, serde_yaml::Value>,
) -> serde_yaml::Value {
    if facts.section != busbar_contract::section::RESERVED_POOLS_KEY {
        return section.clone();
    }
    let mut keyed = serde_yaml::Mapping::new();
    keyed.insert(facts.section.into(), section.clone());
    for name in &facts.consumed {
        if let Some(value) = sections.get(name) {
            keyed.insert((*name).into(), value.clone());
        }
    }
    serde_yaml::Value::Mapping(keyed)
}

/// THE SECTION A DOOR PLANE'S WALK IS SEALED OVER: its declaring section, or, for a plane that
/// declares a `pools` map and reads the `models` map beside it (the previous release's top-level
/// layout), the uniform model-serving section over both (`{models, pools}`, #49).
fn walked_section(
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    section: &serde_yaml::Value,
    sections: &BTreeMap<&'static str, serde_yaml::Value>,
) -> serde_yaml::Value {
    use busbar_contract::section::{RESERVED_MODELS_KEY, RESERVED_POOLS_KEY};
    let models = facts
        .consumed
        .contains(&RESERVED_MODELS_KEY)
        .then(|| sections.get(RESERVED_MODELS_KEY))
        .flatten();
    match models {
        Some(models) if facts.section == RESERVED_POOLS_KEY => {
            let mut uniform = serde_yaml::Mapping::new();
            uniform.insert(RESERVED_MODELS_KEY.into(), models.clone());
            uniform.insert(RESERVED_POOLS_KEY.into(), section.clone());
            serde_yaml::Value::Mapping(uniform)
        }
        _ => section.clone(),
    }
}

/// `open` the plane, generation 1, its settings `section` as JSON, the deployment's `public_url`
/// (absent = none stated) and its `owned` sections; the snapshot it published.
fn open(
    plugin: &DoorPlane,
    section: &serde_yaml::Value,
    public_url: Option<&str>,
    owned: &serde_json::Map<String, serde_json::Value>,
) -> Result<OwnedSnapshot, String> {
    // The reserved `work:` bounds are core-owned: the kernel reads them; the plane never sees them.
    let mut section = section.clone();
    if let Some(map) = section.as_mapping_mut() {
        map.remove(busbar_contract::section::RESERVED_WORK_KEY);
    }
    let settings = serde_json::to_vec(&section).map_err(|e| format!("its section: {e}"))?;
    let owned = if owned.is_empty() {
        Vec::new()
    } else {
        serde_json::to_vec(owned).map_err(|e| format!("its owned sections: {e}"))?
    };
    let url = public_url.unwrap_or_default();
    let mut frame = Frame::new(
        PlaneOpenIn {
            open: OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: Blob {
                    ptr: settings.as_ptr(),
                    len: settings.len(),
                    fmt: BLOB_JSON,
                    flags: 0,
                },
                secrets: std::ptr::null(),
                secrets_len: 0,
                generation: 1,
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            // The deployment's public base URL, which a plane states its audience and its claims
            // against (a plane with none fronts nothing).
            public_url: AbiStr {
                ptr: if url.is_empty() {
                    std::ptr::null()
                } else {
                    url.as_ptr()
                },
                len: url.len(),
            },
            owned: Blob {
                ptr: if owned.is_empty() {
                    std::ptr::null()
                } else {
                    owned.as_ptr()
                },
                len: owned.len(),
                fmt: if owned.is_empty() {
                    busbar_contract::abi::mechanism::call::BLOB_ABSENT
                } else {
                    BLOB_JSON
                },
                flags: 0,
            },
        },
        PlaneOpenOut {
            open: OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                err_len: 0,
            },
            snapshot: std::ptr::null(),
        },
    );
    let (called, snapshot) = plugin.open(&mut frame);
    if called.outcome != AbiOutcome::Ready {
        return Err(format!("it did not open: {:?}", called.outcome));
    }
    snapshot.ok_or_else(|| "its snapshot did not pass the host's checks".to_string())
}

// ── the data routes: a claimed arrival, driven ──────────────────────────────────────────────────

/// THE DOOR PLANES' DATA ROUTES (SERVE-WIRE P2, TODO U6-U7; ARCHITECT Q-SW1 2026-10-02: the route
/// install is the router's construction, no static): every composed plane's snapshot claims, each a
/// line on the data listener's guest list ([`door_routes`]), mounted at construction with its
/// handler. A claimed arrival is one unit of that plane, driven on the process's one node over the
/// plane's [`PlaneDriver`] under its kernel steps ([`DoorSteps`]), its caller's side an
/// [`IngressCaller`]. A plane is served exactly when it is composed, so its door row is its serve
/// switch: a fold adds only its door row (spec K5).
#[cfg(linked_axis_node)]
pub struct DataRoutes {
    served: Served,
    post: Arc<crate::root::plane_node::NodeEndPost>,
    /// The card history a unit is pinned to at its door: the process's (`ROOT_CARD`).
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
    /// The data listener's sealed guest list and each plane line's claim: what a nested unit's
    /// claim is matched against (`unit.nest`, [`DoorNests`]).
    guests: busbar_kernel::guest::GuestList,
    of_line: std::collections::HashMap<(String, u32), DoorClaim>,
    /// The generation each unit in flight was admitted against, by unit key: a nested unit is
    /// admitted against its parent's.
    frames: Mutex<std::collections::HashMap<u64, Arc<busbar_kernel::state::App>>>,
}

/// A unit's generation, kept in [`DataRoutes::frames`] while the unit runs.
#[cfg(linked_axis_node)]
struct UnitFrame<'r> {
    routes: &'r DataRoutes,
    unit: u64,
}

#[cfg(linked_axis_node)]
impl Drop for UnitFrame<'_> {
    fn drop(&mut self) {
        self.routes.frames_lock().remove(&self.unit);
    }
}

/// The most bytes of a nested unit's reply the parent is handed (its whole reply, buffered: THE
/// DESIGN D6): the services' byte bound.
#[cfg(linked_axis_node)]
const NEST_REPLY_MAX: usize = 16 << 20;

/// `unit.nest`'s refusal of a claim nothing on the data listener serves.
pub const NEST_UNSERVED: &str = "no plane serves the nested unit's claim";
/// `unit.nest`'s refusal when the parent is no longer in flight on the node.
pub const NEST_PARENT_GONE: &str = "the nested unit's parent is not in flight";
/// `unit.nest`'s FAILED answer of a child whose reply could not be read whole.
pub const NEST_UNREAD: &str = "the nested unit's reply could not be read";

/// THE ROOT'S NESTED-DISPATCH SEAM (THE DESIGN §11.12 unit row; ARCHITECT H3 "NestRoute root seam";
/// ARCHITECT round 4 (c)): a nested unit's claim matched on the data listener's guest list, the
/// child driven on the process's one node as a door unit of the plane that claims it, under the
/// parent's principal and generation, its hold cell accruing against the parent's, its whole reply
/// buffered and handed back. The kernel never learns what the child is.
#[cfg(linked_axis_node)]
pub struct DoorNests {
    routes: std::sync::Weak<DataRoutes>,
    runtime: tokio::runtime::Handle,
}

#[cfg(linked_axis_node)]
impl busbar_kernel::host_services::NestRoute for DoorNests {
    fn nest(
        &self,
        nest: busbar_kernel::host_services::Nest,
        done: busbar_kernel::host_services::NestDone,
    ) {
        let Some(routes) = self.routes.upgrade() else {
            done(busbar_kernel::host_services::NestReply::Unserved(
                NEST_UNSERVED,
            ));
            return;
        };
        drop(
            self.runtime
                .spawn(async move { done(routes.nested(nest).await) }),
        );
    }
}

#[cfg(linked_axis_node)]
impl std::fmt::Debug for DataRoutes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataRoutes")
            .field("served", &self.served)
            .finish_non_exhaustive()
    }
}

/// THE DATA ROUTES THIS PROCESS'S DATA ROUTER IS BUILT WITH ([`door_routes`], pinned to the
/// process's card history): none when no composed plane claims a route.
///
/// # Errors
///
/// A claim the data listener cannot mount, two claims at an equal precedence, or (a build with no
/// node) any claim at all: no unit could be driven for it.
pub fn data_routes(
    served: Served,
    data_chain: &[String],
    core: &[(
        String,
        busbar_contract::abi::mechanism::route::RouteMethod,
        busbar_contract::abi::mechanism::route::RouteAuth,
    )],
) -> Result<Vec<busbar_kernel::plane_routes::PlaneRouteSpec>, String> {
    if served.planes.iter().all(|p| p.snapshot.claims.is_empty()) {
        return Ok(Vec::new());
    }
    #[cfg(linked_axis_node)]
    {
        door_routes(
            served,
            || crate::root::kernel::ROOT_CARD.pin(),
            data_chain,
            core,
        )
    }
    #[cfg(not(linked_axis_node))]
    {
        let _ = (data_chain, core);
        Err(
            "a door plane's units are driven on the process's node, and this build links none"
                .to_string(),
        )
    }
}

/// [`data_routes`], and the door planes' session routes beside them (ARCHITECT Q-L5B-SESSION-SERVE;
/// TRANSITIONAL: deleted when INBOUND-LISTEN's accepted::Caller serves): what the data router is
/// built with.
///
/// # Errors
///
/// As [`data_routes`].
pub fn data_mounts(
    served: Served,
    data_chain: &[String],
    core: &[(
        String,
        busbar_contract::abi::mechanism::route::RouteMethod,
        busbar_contract::abi::mechanism::route::RouteAuth,
    )],
    upgrades: &[&str],
) -> Result<
    (
        Vec<busbar_kernel::plane_routes::PlaneRouteSpec>,
        Vec<busbar_kernel::plane_routes::PlaneSessionSpec>,
    ),
    String,
> {
    if served.planes.iter().all(|p| p.snapshot.claims.is_empty()) {
        return Ok((Vec::new(), Vec::new()));
    }
    #[cfg(linked_axis_node)]
    {
        door_mounts(
            served,
            || crate::root::kernel::ROOT_CARD.pin(),
            data_chain,
            core,
            upgrades,
        )
        .map(|m| (m.routes, m.sessions))
    }
    #[cfg(not(linked_axis_node))]
    {
        let _ = (data_chain, core, upgrades);
        Err(
            "a door plane's units are driven on the process's node, and this build links none"
                .to_string(),
        )
    }
}

/// ONE DATA REQUEST on a door plane's claim, as its route handed it over: the credentials the auth
/// gate consumed already struck, its verdict on the caller, and the generation serving it (its cost
/// model, governance book and groups).
#[cfg(linked_axis_node)]
pub struct DoorRequest {
    /// The verb.
    pub method: axum::http::Method,
    /// The target, as it arrived.
    pub uri: axum::http::Uri,
    /// The head fields.
    pub headers: axum::http::HeaderMap,
    /// The body, read under the inbound body limit.
    pub body: Bytes,
    /// The auth gate's verdict for the caller.
    pub gov: busbar_contract::records::PlaneRequestCtx,
    /// The caller's verified credential, lent for a passthrough member's outbound auth call alone.
    pub credential: Option<busbar_contract::redacted::Redacted<Vec<u8>>>,
    /// The generation serving the request.
    pub app: Arc<busbar_kernel::state::App>,
}

/// THE AUTH ON A DOOR CLAIM'S GUEST-LIST LINE (THE DESIGN §6, "Auth points and guest lists"): the
/// operator's data chain (`auth.chain`) is the auth of every data-listener line; only where it gives
/// the line none does the claim's own declared default inbound style apply. `CLAIM_OPEN` declares
/// none; any other claim takes a credential, verified by the deployment's (empty) chain.
#[cfg(linked_axis_node)]
fn line_auth(flags: u32, data_chain: &[String]) -> busbar_kernel::guest::LineAuth {
    use busbar_kernel::guest::LineAuth;
    if data_chain.is_empty() && flags & CLAIM_OPEN != 0 {
        LineAuth::None
    } else {
        LineAuth::Chain(data_chain.to_vec())
    }
}

/// The claimant the kernel's own data routes are lines of.
#[cfg(linked_axis_node)]
const CORE_CLAIMANT: &str = "core";

/// The data listener's own framer: a claim over a carrier that composes over it is an upgrade line.
const DATA_CARRIER: &str = "http";

/// THE UPGRADE CARRIERS: the linked wires that compose over the data listener's own framer, whose
/// claims are upgrade lines (their connection handed over after the head) and served as sessions.
#[must_use]
pub fn upgrade_carriers(transports: &[crate::root::linked::LinkedTransport]) -> Vec<&'static str> {
    transports
        .iter()
        .filter(|t| t.composes_over.contains(&DATA_CARRIER))
        .map(|t| t.key)
        .collect()
}

/// How many messages a session route's pipe queues each way before the sender waits.
#[cfg(linked_axis_node)]
const SESSION_QUEUE: usize = 64;

/// The name of a subtree claim's tail capture.
#[cfg(linked_axis_node)]
const SUBTREE: &str = "rest";

/// The methods the data listener mounts a door claim under.
#[cfg(linked_axis_node)]
const METHODS: [RouteMethod; 5] = [
    RouteMethod::Get,
    RouteMethod::Post,
    RouteMethod::Put,
    RouteMethod::Patch,
    RouteMethod::Delete,
];

/// The guest-list line a plane's claim writes on the data listener, and the method the data router
/// mounts it under.
#[cfg(linked_axis_node)]
fn claim_line(
    instance: &str,
    rung: u32,
    claim: &crate::root::loader::dispatch::kinds::plane::OwnedClaim,
    data_chain: &[String],
    upgrades: &[&str],
) -> Result<(busbar_kernel::guest::Line, RouteMethod), String> {
    use busbar_contract::abi::transport::route::{method_bit, PATH_EXACT, PATH_PATTERN};
    let method = METHODS
        .into_iter()
        .find(|m| m.as_str() == claim.verb)
        .ok_or_else(|| {
            format!(
                "{instance}: claim {} {} names a verb the data listener does not serve",
                claim.verb, claim.target
            )
        })?;
    let exact = claim.flags & CLAIM_EXACT != 0;
    let pattern = claim.flags & CLAIM_PATTERN != 0;
    let line = busbar_kernel::guest::Line {
        route: busbar_kernel::guest::Route {
            methods: method_bit(&claim.verb),
            // An exact claim is its target; a pattern claim is its target, each `{name}` one
            // segment (`CLAIM_PATTERN`); any other is its target's whole subtree, at any depth (the
            // guest list's tail pattern, which matches what remains, including nothing).
            path_form: if exact { PATH_EXACT } else { PATH_PATTERN },
            path: if exact || pattern {
                claim.target.clone()
            } else {
                format!("{}/{{*{SUBTREE}}}", claim.target.trim_end_matches('/'))
            },
            fields: Vec::new(),
            rung,
        },
        claimant: busbar_kernel::guest::Claimant::Plane(instance.to_string()),
        dialect: u32::from(claim.refusal_dialect),
        auth: line_auth(claim.flags, data_chain),
        // A claim over a carrier that composes over the data listener's own framer is an UPGRADE
        // line: the connection is handed to that carrier after the head, served as a duplex
        // session.
        upgrade: upgrades
            .contains(&claim.carrier.as_str())
            .then(|| claim.carrier.clone()),
    };
    Ok((line, method))
}

/// One claim's route: the plane it is of and the claim's index in its snapshot.
#[cfg(linked_axis_node)]
type DoorClaim = (usize, u32);

/// THE DOOR PLANES' DATA ROUTES (ARCHITECT Q-SW1, 2026-10-02): every claim of every served plane is
/// a line on the data listener's guest list (sealed: two claims that could meet at an equal
/// precedence refuse the boot), mounted at its line's path and auth, its handler the plane's unit
/// on the node, posted through `post` and pinned to the card `pin` answers. An exact claim mounts
/// its target; any other its target and the whole subtree under it, at any depth. The kernel's own
/// data routes (`core`) are lines on the same list, and a method the list gives one is never a door
/// mount. The data router is built once, with these in it (`build_split_routers_serving`).
///
/// # Errors
///
/// A claim the data listener cannot mount, or two claims at an equal precedence, named: the boot
/// refuses it.
#[cfg(linked_axis_node)]
pub fn door_routes(
    served: Served,
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
    data_chain: &[String],
    core: &[(String, RouteMethod, RouteAuth)],
) -> Result<Vec<PlaneRouteSpec>, String> {
    door_mounts(served, pin, data_chain, core, &[]).map(|m| m.routes)
}

/// WHAT THE DATA ROUTER MOUNTS FOR THE DOOR PLANES at its construction: their request routes, and
/// their duplex SESSION routes (an upgrade line's claim; ARCHITECT Q-L5B-SESSION-SERVE, TRANSITIONAL:
/// deleted when INBOUND-LISTEN's accepted::Caller serves).
#[cfg(linked_axis_node)]
pub struct DoorMounts {
    /// The request routes.
    pub routes: Vec<PlaneRouteSpec>,
    /// The session routes.
    pub sessions: Vec<busbar_kernel::plane_routes::PlaneSessionSpec>,
}

#[cfg(linked_axis_node)]
impl std::fmt::Debug for DoorMounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorMounts")
            .field("routes", &self.routes.len())
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

/// [`door_routes`], and the door planes' session routes beside them ([`DoorMounts`]): a claim on an
/// upgrade line is mounted as a GET session route, every other claim as the request route it was.
///
/// # Errors
///
/// As [`door_routes`].
#[cfg(linked_axis_node)]
pub fn door_mounts(
    served: Served,
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
    data_chain: &[String],
    core: &[(String, RouteMethod, RouteAuth)],
    upgrades: &[&str],
) -> Result<DoorMounts, String> {
    use busbar_contract::abi::transport::route::{method_bit, PATH_EXACT, PATH_PATTERN};
    use busbar_kernel::guest::{Claimant, GuestList, GuestRefusal, LineAuth, Matched};
    use std::collections::HashMap;
    // THE PUBLIC ROUTES the served planes state (SEAM-4o): each at its own target on the data
    // listener, open to a caller that presents no busbar credential, served by the plane's `serve`.
    let public = public_routes(&served);
    if served.planes.iter().all(|p| p.snapshot.claims.is_empty()) {
        return Ok(DoorMounts {
            routes: public,
            sessions: Vec::new(),
        });
    }
    let mut upgraded: std::collections::HashSet<DoorClaim> = std::collections::HashSet::new();
    let mut lines = Vec::new();
    let mut doors: Vec<(busbar_kernel::guest::Line, RouteMethod, DoorClaim)> = Vec::new();
    for (p, plane) in served.planes.iter().enumerate() {
        for (i, claim) in plane.snapshot.claims.iter().enumerate() {
            let rung =
                u32::try_from(i).map_err(|_| format!("{}: too many claims", plane.instance))?;
            let (line, method) = claim_line(&plane.instance, rung, claim, data_chain, upgrades)?;
            if line.upgrade.is_some() {
                upgraded.insert((p, rung));
            }
            lines.push(line.clone());
            doors.push((line, method, (p, rung)));
        }
    }
    // The kernel's own data routes, lines of the core's claimant (a cleanliness crate's route,
    // THE DESIGN §6).
    for (rung, (path, method, auth)) in (0u32..).zip(core) {
        lines.push(busbar_kernel::guest::Line {
            route: busbar_kernel::guest::Route {
                methods: method_bit(method.as_str()),
                path_form: if path.contains('{') {
                    PATH_PATTERN
                } else {
                    PATH_EXACT
                },
                path: path.clone(),
                fields: Vec::new(),
                rung,
            },
            claimant: Claimant::Clean(CORE_CLAIMANT.to_string()),
            dialect: 0,
            auth: match auth {
                RouteAuth::None => LineAuth::None,
                _ => LineAuth::Chain(data_chain.to_vec()),
            },
            upgrade: None,
        });
    }
    let guests = GuestList::seal(lines).map_err(|refusal| match refusal {
        GuestRefusal::EqualPrecedence(pair) => format!(
            "the data listener's claims {:?} {} and {:?} {} meet at an equal precedence",
            pair.0.claimant, pair.0.route.path, pair.1.claimant, pair.1.route.path
        ),
    })?;
    let post = served.post.clone().unwrap_or_else(|| {
        Arc::new(crate::root::plane_node::NodeEndPost::new(
            crate::root::plane_node::node(),
        ))
    });
    let instances: Vec<String> = served.planes.iter().map(|p| p.instance.clone()).collect();
    let documents = resource_documents(&served);
    // Every mount: an exact line at its one path; a subtree line at its target and its tail.
    let mut mounts: Vec<(String, RouteMethod, RouteAuth, DoorClaim)> = Vec::new();
    let mut of_line: HashMap<(String, u32), (RouteAuth, DoorClaim)> = HashMap::new();
    for (line, method, door) in doors {
        let auth = match line.auth {
            LineAuth::None => RouteAuth::None,
            LineAuth::Chain(_) => RouteAuth::Key,
        };
        let tail = format!("/{{*{SUBTREE}}}");
        let paths = if line.route.path_form == PATH_EXACT || !line.route.path.ends_with(&tail) {
            vec![line.route.path.clone()]
        } else {
            let target = line.route.path.trim_end_matches(&tail).to_string();
            let target = if target.is_empty() {
                "/".to_string()
            } else {
                target
            };
            vec![target, line.route.path.clone()]
        };
        // One mount per (path, method): a plane's claims on one verb and path that differ only by
        // the carrier they arrive over (an endpoint answered as a document or as an event stream)
        // are one route on the data listener, the first in the plane's claim order; which carrier
        // answers is the plane's to decide from the request, as the data door never compared it.
        for path in paths {
            if !mounts.iter().any(|(p, m, ..)| *p == path && *m == method) {
                mounts.push((path, method, auth, door));
            }
        }
        of_line.insert((instances[door.0].clone(), line.route.rung), (auth, door));
    }
    // THE GUEST LIST DECIDES, NOT THE ROUTER: at a concrete path one line names, a method no line
    // mounts there is the line the guest list matches for that path and method (a line that
    // matches the path and not the method is passed over), never the router's own 405.
    let concrete: Vec<String> = mounts
        .iter()
        .map(|(path, ..)| path.clone())
        .filter(|path| !path.contains('{'))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    for path in concrete {
        for method in METHODS {
            if mounts.iter().any(|(p, m, ..)| *p == path && *m == method) {
                continue;
            }
            let Matched::Line(line) = guests.matched(method.as_str(), &path, &[]) else {
                continue;
            };
            let Claimant::Plane(instance) = &line.claimant else {
                continue;
            };
            if let Some((auth, door)) = of_line.get(&(instance.clone(), line.route.rung)) {
                mounts.push((path.clone(), method, *auth, *door));
            }
        }
    }
    let kernel = served.planes.first().map(|p| Arc::clone(&p.kernel));
    let routes = Arc::new(DataRoutes {
        served,
        post,
        pin,
        guests,
        of_line: of_line
            .into_iter()
            .map(|(line, (_, door))| (line, door))
            .collect(),
        frames: Mutex::default(),
    });
    // THE NESTED-DISPATCH SEAM, attached once to the kernel's services: `unit.nest` runs a child
    // on these routes, on the runtime the routes are built on.
    if let (Some(kernel), Ok(runtime)) = (kernel, tokio::runtime::Handle::try_current()) {
        let _attached = kernel.attach_nest(Arc::new(DoorNests {
            routes: Arc::downgrade(&routes),
            runtime,
        }));
    }
    let mut sessions = Vec::new();
    let mut requests = Vec::new();
    for mount in mounts {
        let (path, method, auth, door) = mount;
        if !upgraded.contains(&door) {
            requests.push((path, method, auth, door));
            continue;
        }
        // An upgrade is an HTTP GET: the session route answers that verb alone.
        if method != RouteMethod::Get {
            continue;
        }
        let routes = Arc::clone(&routes);
        let (plane, claim) = door;
        sessions.push(busbar_kernel::plane_routes::PlaneSessionSpec {
            path,
            auth,
            handler: Arc::new(
                move |ctx: PlaneReqCtx| -> busbar_kernel::plane_routes::PlaneSessionFuture {
                    let routes = Arc::clone(&routes);
                    Box::pin(async move {
                        match DoorRequest::of(ctx) {
                            Some(req) => routes.open_session(plane, claim, req).await,
                            None => busbar_kernel::plane_routes::SessionAnswer::Refused(stated(
                                (refusal_status(ReasonCode::PlanePanic), Vec::new()),
                                Body::empty(),
                            )),
                        }
                    })
                },
            ),
        });
    }
    let routes_of = requests
        .into_iter()
        .map(|(path, method, auth, (plane, claim))| {
            // THE PROTECTED-RESOURCE DOCUMENT (ARCHITECT Q-L3B-RFC9728): rendered by the kernel's
            // one RFC 9728 renderer from the facts the door states; not a unit, no audit row.
            if let Some(doc) = documents.get(&(plane, claim)).cloned() {
                return PlaneRouteSpec {
                    path,
                    method,
                    auth,
                    handler: Arc::new(move |_ctx: PlaneReqCtx| -> PlaneRouteFuture {
                        let doc = Arc::clone(&doc);
                        Box::pin(async move {
                            busbar_kernel::ingress::protocol::metadata(
                                &busbar_kernel::ingress::protocol::Metadata {
                                    resource: std::borrow::Cow::Borrowed(&doc.resource),
                                    authorization_servers: &doc.authorization_servers,
                                    scopes_supported: &doc.scopes_supported,
                                },
                            )
                        })
                    }),
                };
            }
            let routes = Arc::clone(&routes);
            PlaneRouteSpec {
                path,
                method,
                auth,
                handler: Arc::new(move |ctx: PlaneReqCtx| -> PlaneRouteFuture {
                    let routes = Arc::clone(&routes);
                    Box::pin(async move {
                        match DoorRequest::of(ctx) {
                            Some(req) => routes.answer(plane, claim, req).await,
                            None => stated(
                                (refusal_status(ReasonCode::PlanePanic), Vec::new()),
                                Body::empty(),
                            ),
                        }
                    })
                }),
            }
        })
        .collect::<Vec<_>>();
    let mut routes_of = routes_of;
    routes_of.extend(public);
    Ok(DoorMounts {
        routes: routes_of,
        sessions,
    })
}

/// THE PUBLIC ROUTES the served door planes state (`abi::plane::ROUTE_PUBLIC`, SEAM-4o): each at its
/// own target and verb on the data listener's mount, behind no auth gate (`RouteAuth::None`; the
/// listener's arrival gates still apply), answered by the plane's `serve` op through the kernel's
/// public serve path. A verb the router does not mount is left out.
#[cfg(linked_axis_node)]
fn public_routes(served: &Served) -> Vec<PlaneRouteSpec> {
    served
        .planes
        .iter()
        .flat_map(|p| p.snapshot.admin_routes.iter())
        .filter(|r| r.flags & busbar_contract::abi::plane::ROUTE_PUBLIC != 0)
        .filter_map(|r| {
            let method = METHODS
                .into_iter()
                .find(|m| m.as_str().eq_ignore_ascii_case(&r.verb))?;
            // The scheme its callers are verified under (spec Part 3 "Inbound webhooks"); none: the
            // route is served to an unauthenticated caller, as before.
            let scheme: Option<Arc<str>> =
                (!r.style.is_empty()).then(|| Arc::from(r.style.as_str()));
            Some(PlaneRouteSpec {
                path: r.target.clone(),
                method,
                auth: RouteAuth::None,
                handler: Arc::new(move |ctx: PlaneReqCtx| -> PlaneRouteFuture {
                    let scheme = scheme.clone();
                    Box::pin(async move {
                        let head = match scheme {
                            Some(scheme) => {
                                match crate::root::public_verify::verified(&scheme, &ctx).await {
                                    Ok(head) => head,
                                    Err(status) => {
                                        return axum::response::IntoResponse::into_response(status)
                                    }
                                }
                            }
                            None => ctx.headers.clone(),
                        };
                        let target = ctx
                            .uri
                            .path_and_query()
                            .map_or_else(|| ctx.path.clone(), |pq| pq.as_str().to_string());
                        busbar_kernel::plane_driver::serve::answer_public(
                            ctx.method.as_str(),
                            &ctx.path,
                            &target,
                            &head,
                            ctx.body,
                        )
                        .await
                    })
                }),
            })
        })
        .collect()
}

/// A door plane's RFC 9728 facts: its audience and the authorization servers and scopes it states.
struct ResourceDocument {
    resource: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
}

/// THE PROTECTED-RESOURCE DOCUMENTS the served door planes state, by `(plane, claim)`: an open GET
/// claim at the path of the plane's `resource_metadata`, beside the audience it binds, with the
/// facts its snapshot states (`resource_facts`, absent = none).
fn resource_documents(
    served: &Served,
) -> std::collections::HashMap<(usize, u32), Arc<ResourceDocument>> {
    let mut out = std::collections::HashMap::new();
    for (p, plane) in served.planes.iter().enumerate() {
        let snapshot = &plane.snapshot;
        let (Some(resource), Some(metadata)) = (&snapshot.audience, &snapshot.resource_metadata)
        else {
            continue;
        };
        let after = metadata.find("://").map_or(0, |at| at + 3);
        let path = metadata[after..]
            .find('/')
            .map_or("/", |at| &metadata[after + at..]);
        let facts: serde_json::Value = snapshot
            .resource_facts
            .as_deref()
            .and_then(|f| serde_json::from_slice(f).ok())
            .unwrap_or_default();
        let list = |key: &str| -> Vec<String> {
            facts
                .get(key)
                .and_then(serde_json::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        let doc = Arc::new(ResourceDocument {
            resource: resource.clone(),
            authorization_servers: list("authorization_servers"),
            scopes_supported: list("scopes_supported"),
        });
        for (i, claim) in snapshot.claims.iter().enumerate() {
            let open = claim.flags & busbar_contract::abi::plane::CLAIM_OPEN != 0;
            if open && claim.verb == "GET" && claim.target == path {
                if let Ok(rung) = u32::try_from(i) {
                    out.insert((p, rung), Arc::clone(&doc));
                }
            }
        }
    }
    out
}

#[cfg(linked_axis_node)]
impl DoorRequest {
    /// The request a door claim's route was handed (`None` when its engine is not the kernel's).
    fn of(ctx: PlaneReqCtx) -> Option<Self> {
        let app = ctx
            .engine
            .downcast::<busbar_kernel::state::AppHandle>()
            .ok()?
            .load();
        Some(DoorRequest {
            method: axum::http::Method::from_bytes(ctx.method.as_str().as_bytes()).ok()?,
            uri: ctx.uri,
            headers: ctx.headers,
            body: ctx.body,
            gov: ctx.gov.unwrap_or_default(),
            credential: ctx.caller_credential,
            app,
        })
    }
}

#[cfg(linked_axis_node)]
impl DataRoutes {
    /// ONE DUPLEX SESSION ARRIVAL (K6; ARCHITECT Q-L5B-SESSION-SERVE 2026-10-03, TRANSITIONAL with
    /// the session routes): the caller's head delivered once at `arrive`, as a request's is; the
    /// session's unit opened on the node (its steps to the door, one admission) on its own task,
    /// which holds the unit for the session's whole life. A refusal answers before any upgrade, in
    /// the plane's rendering; an admission hands the core the pipe its upgraded socket is bridged
    /// onto, whose other ends are the session's [`PipeCaller`].
    async fn open_session(
        self: Arc<Self>,
        plane: usize,
        claim: u32,
        req: DoorRequest,
    ) -> busbar_kernel::plane_routes::SessionAnswer {
        use busbar_kernel::plane_routes::{SessionAnswer, SessionPipe};
        let DoorRequest {
            method,
            uri,
            headers,
            body,
            gov,
            credential,
            app,
        } = req;
        let fields: HeadFields = headers
            .iter()
            .filter(|(n, _)| !NEVER_KEPT.contains(&n.as_str()))
            .map(|(n, v)| (n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        let target = uri.path_and_query().map_or(uri.path(), |t| t.as_str());
        let arrival = Arrival {
            claim,
            method: method.as_str().as_bytes().to_vec(),
            target: target.as_bytes().to_vec(),
            fields,
            body: Arc::from(&body[..]),
        };
        let principal = match gov.key() {
            Some(key) => PrincipalId::new(key.id.as_str()),
            None => PrincipalId::new(AuthPrincipal(None).actor_id()),
        };
        // An anonymous caller is admitted on an open claim; and, on the plane serving the `pools`
        // map, on every claim when the deployment's data front door is open (`auth.chain: []`
        // without `keys`: 1.5.5 admitted every model request anonymously, its open relay). Any
        // other plane's credential claim fails closed (ARCHITECT P3 (a)).
        let pools_plane = self.served.planes[plane].live.served_facts.section
            == busbar_contract::section::RESERVED_POOLS_KEY;
        let open = (pools_plane && app.auth.is_open())
            || self.served.planes[plane]
                .snapshot
                .claims
                .get(claim as usize)
                .is_some_and(|c| c.flags & CLAIM_OPEN != 0);
        let key = gov.key.clone();
        let (from_caller, from_rx) = mpsc::channel(SESSION_QUEUE);
        let (to_tx, to_caller) = mpsc::channel(SESSION_QUEUE);
        let caller = PipeCaller {
            from: tokio::sync::Mutex::new(from_rx),
            to: to_tx,
        };
        let (verdict, said) = oneshot::channel();
        let door = SessionDoor {
            plane,
            app,
            principal,
            key,
            open,
            credential,
        };
        tokio::spawn(self.session(door, caller, arrival, verdict));
        match said.await {
            Ok(Ok(())) => SessionAnswer::Accepted(SessionPipe {
                from_caller,
                to_caller,
            }),
            Ok(Err(Some(rendered))) => SessionAnswer::Refused(stated(
                (rendered.status, rendered.fields),
                Body::from(rendered.body),
            )),
            Ok(Err(None)) | Err(_) => SessionAnswer::Refused(stated(
                (refusal_status(ReasonCode::PlanePanic), Vec::new()),
                Body::empty(),
            )),
        }
    }

    /// THE SESSION, on its own task: its unit's kernel steps over the plane's tail, pools and money,
    /// its far end the plane's egress (the turn legs' one dial, held), opened on the node through the
    /// session opener; `verdict` told what the door said before the session runs; the session pumped
    /// through the plane driver's two tickets until either side ends; its slot given back, and its
    /// money settled (the session's one line was written at its end; the fee by the plane's report).
    async fn session(
        self: Arc<Self>,
        door: SessionDoor,
        caller: PipeCaller,
        arrival: Arrival,
        verdict: oneshot::Sender<Result<(), Option<Rendered>>>,
    ) {
        use busbar_kernel::teller::SessionOpen;
        let served = &self.served.planes[door.plane];
        let live = served.live.current();
        let node = self.post.node();
        let unit = node.mint();
        let arrived = node.arrived();
        let steps = DoorSteps::new(
            &served.facts,
            &live.pools,
            node.resolver(),
            door.app,
            Some(&*served.money),
            DoorCaller {
                principal: door.principal.clone(),
                key: door.key,
                open: door.open,
                arrived: arrived.secs(),
                records: Some(Arc::clone(served.kernel.units())),
                depth: 0,
                credential: door.credential.clone(),
            },
        );
        let far = DoorFar {
            egress: live.egress.as_deref(),
            shown: live.shown.as_ref(),
            steps: &steps,
            unit,
            credential: door.credential,
            far: OnceLock::new(),
        };
        let units = served.driver.unit(&steps, &far, &caller, arrival, 0);
        let Some((opened, ctx, slot)) = node.open_borrowed(
            unit,
            arrived,
            &door.principal,
            &self.post,
            &units,
            (self.pin)(),
        ) else {
            let _ = verdict.send(Err(None));
            return;
        };
        let status = match opened {
            // The open's hook stage (K5, ARCHITECT Q-L5B-PROJECT) runs before the caller is
            // answered: a hook that stops it is answered in the plane's rendering, never upgraded.
            SessionOpen::Admitted {
                route,
                destinations,
            } if units.open_hooks(&route, &ctx).await.is_ok() => {
                let _ = verdict.send(Ok(()));
                let _ended = units.session(&route, &ctx, &destinations).await;
                SWITCHED
            }
            _ => {
                let rendered = units.take_rendered();
                let status = rendered
                    .as_ref()
                    .map_or_else(|| refusal_status(ReasonCode::PlanePanic), |r| r.status);
                let _ = verdict.send(Err(rendered));
                status
            }
        };
        slot.finish(&self.post);
        served.money.settle_end(unit, status);
    }

    /// ONE CLAIMED ARRIVAL, SERVED: the caller's head (the credentials the auth gate consumed and
    /// the fields never kept struck), delivered once at `arrive`; the caller the auth gate
    /// resolved; the unit driven inside the response, so a caller that goes away drops it.
    async fn answer(self: Arc<Self>, plane: usize, claim: u32, req: DoorRequest) -> Response {
        let DoorRequest {
            method,
            uri,
            headers,
            body,
            gov,
            credential,
            app,
        } = req;
        let fields: HeadFields = headers
            .iter()
            .filter(|(n, _)| !NEVER_KEPT.contains(&n.as_str()))
            .map(|(n, v)| (n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        let target = uri.path_and_query().map_or(uri.path(), |t| t.as_str());
        let arrival = Arrival {
            claim,
            method: method.as_str().as_bytes().to_vec(),
            target: target.as_bytes().to_vec(),
            fields,
            body: Arc::from(&body[..]),
        };
        let principal = match gov.key() {
            Some(key) => PrincipalId::new(key.id.as_str()),
            None => PrincipalId::new(AuthPrincipal(None).actor_id()),
        };
        // An anonymous caller is admitted on an open claim; and, on the plane serving the `pools`
        // map, on every claim when the deployment's data front door is open (`auth.chain: []`
        // without `keys`: 1.5.5 admitted every model request anonymously, its open relay). Any
        // other plane's credential claim fails closed (ARCHITECT P3 (a)).
        let pools_plane = self.served.planes[plane].live.served_facts.section
            == busbar_contract::section::RESERVED_POOLS_KEY;
        let open = (pools_plane && app.auth.is_open())
            || self.served.planes[plane]
                .snapshot
                .claims
                .get(claim as usize)
                .is_some_and(|c| c.flags & CLAIM_OPEN != 0);
        let key = gov.key.clone();
        // A STREAM ANOTHER FRAMER FRAMES (ARCHITECT 4l): the claim's carrier is answered by a
        // framer that is not the data listener's own; that framer frames this stream alone.
        let carrier = self.served.planes[plane]
            .snapshot
            .claims
            .get(claim as usize)
            .map(|c| c.carrier.clone());
        if let Some((door, carrier)) = carrier.and_then(|c| {
            serve_framed::stream_framer(&c, DATA_CARRIER, |s| self.framer_for(s)).map(|d| (d, c))
        }) {
            let head: Vec<(String, Vec<u8>)> = arrival
                .fields
                .iter()
                .map(|(n, v)| (String::from_utf8_lossy(n).into_owned(), v.clone()))
                .collect();
            let target = String::from_utf8_lossy(&arrival.target).into_owned();
            let Ok(mut stream) = busbar_core_connector::framed_stream::FramedStream::open(
                door, &carrier, &target, &head,
            ) else {
                return stated(
                    (refusal_status(ReasonCode::DecodeFailed), Vec::new()),
                    Body::empty(),
                );
            };
            let messages = match stream.ingest(&body, true) {
                Ok(messages) => messages,
                Err(why) => {
                    let status = refusal_status(ReasonCode::DecodeFailed);
                    return match stream.refuse(why.error.as_bytes(), status) {
                        Ok(block) => serve_framed::whole(status, &block),
                        Err(_) => stated((status, Vec::new()), Body::empty()),
                    };
                }
            };
            let arrival = Arrival {
                body: Arc::from(messages.concat()),
                ..arrival
            };
            let stream: serve_framed::Shared = Arc::new(Mutex::new(Some(stream)));
            let (inner, reply) = IngressCaller::arriving(body);
            let (trailers, trailed) = oneshot::channel();
            let caller = serve_framed::FramedCaller::new(inner, Arc::clone(&stream), trailers);
            let unit = async move {
                let caller = caller;
                self.drive(
                    plane,
                    app,
                    (principal, key, credential),
                    open,
                    &caller,
                    arrival,
                    None,
                )
                .await
            };
            return reply
                .with_trailers(trailed)
                .answer_with(Box::pin(unit), move |rendered| {
                    serve_framed::refused(&stream, rendered)
                })
                .await;
        }
        let (caller, reply) = IngressCaller::arriving(body);
        let unit = async move {
            let caller = caller;
            self.drive(
                plane,
                app,
                (principal, key, credential),
                open,
                &caller,
                arrival,
                None,
            )
            .await
        };
        reply.answer(Box::pin(unit)).await
    }

    /// The framer that answers the claim `scheme`: the served planes' resolver, else the process's
    /// one connector's.
    fn framer_for(
        &self,
        scheme: &str,
    ) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>> {
        match &self.served.framers {
            Some(f) => (f.0)(scheme),
            None => crate::root::connector::the().framer_for(scheme),
        }
    }

    fn frames_lock(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<u64, Arc<busbar_kernel::state::App>>>
    {
        self.frames
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// ONE NESTED UNIT (`unit.nest`): its claim matched on the guest list, driven as a door unit of
    /// the plane that claims it under the parent's principal and generation, a child of the
    /// parent's hold cell, one level deeper; its whole reply read and handed back.
    async fn nested(
        self: Arc<Self>,
        nest: busbar_kernel::host_services::Nest,
    ) -> busbar_kernel::host_services::NestReply {
        use busbar_kernel::guest::{Claimant, Matched};
        use busbar_kernel::host_services::NestReply;
        let path = nest.ask.target.split('?').next().unwrap_or_default();
        let door = match self.guests.matched(&nest.ask.verb, path, &[]) {
            Matched::Line(line) => match &line.claimant {
                Claimant::Plane(instance) => self
                    .of_line
                    .get(&(instance.clone(), line.route.rung))
                    .copied(),
                _ => None,
            },
            _ => None,
        };
        let Some((plane, claim)) = door else {
            return NestReply::Unserved(NEST_UNSERVED);
        };
        let parent_key = busbar_contract::UnitKey::new(nest.parent);
        let (Some(app), Some(parent)) = (
            self.frames_lock().get(&nest.parent).cloned(),
            self.post.node().parent(parent_key),
        ) else {
            return NestReply::Unserved(NEST_PARENT_GONE);
        };
        let principal = match nest.principal.as_deref() {
            Some(key) => PrincipalId::new(key.id.as_str()),
            None => PrincipalId::new(AuthPrincipal(None).actor_id()),
        };
        let open = self.served.planes[plane]
            .snapshot
            .claims
            .get(claim as usize)
            .is_some_and(|c| c.flags & CLAIM_OPEN != 0);
        let arrival = Arrival {
            claim,
            method: nest.ask.verb.into_bytes(),
            target: nest.ask.target.into_bytes(),
            fields: Vec::new(),
            body: Arc::from(nest.ask.body),
        };
        let nesting = Nesting {
            parent,
            depth: nest.depth,
        };
        let key = nest.principal;
        let (caller, reply) = IngressCaller::new();
        let routes = Arc::clone(&self);
        let unit = async move {
            let caller = caller;
            routes
                .drive(
                    plane,
                    app,
                    // A nested unit presents no credential of its own: nothing is lent to a
                    // passthrough member on its behalf.
                    (principal, key, None),
                    open,
                    &caller,
                    arrival,
                    Some(nesting),
                )
                .await
        };
        let response = reply.answer(Box::pin(unit)).await;
        let (parts, body) = response.into_parts();
        let Ok(body) = axum::body::to_bytes(body, NEST_REPLY_MAX).await else {
            return NestReply::Unserved(NEST_UNREAD);
        };
        NestReply::Answered {
            status: u32::from(parts.status.as_u16()),
            fields: parts
                .headers
                .iter()
                .map(|(n, v)| (n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect(),
            body: body.to_vec(),
        }
    }

    /// THE UNIT, on the process's one node (SERVE-WIRE step 33): its kernel steps over the plane's
    /// tail, pools and money, its far end the plane's egress, driven through the loop by the node's
    /// borrowed drive; its one line posted there with what it consumed; its money settled on the
    /// money steps by its caller status (the ledger and the plane's fee rule). What it rendered for
    /// its caller, when it ended before any byte.
    ///
    /// A NESTED unit (`nesting`) is a child of its parent: it runs one level deeper, its door
    /// accrues against the parent's hold cell, and the node drives it under the parent.
    #[allow(clippy::too_many_arguments)]
    async fn drive<C: SessionCaller + Stated + Send + Sync>(
        &self,
        plane: usize,
        app: Arc<busbar_kernel::state::App>,
        (principal, key, credential): UnitCaller,
        open: bool,
        caller: &C,
        arrival: Arrival,
        nesting: Option<Nesting>,
    ) -> Option<Rendered> {
        let served = &self.served.planes[plane];
        // The generation this unit is served by, held to its end.
        let live = served.live.current();
        let started = std::time::Instant::now();
        let claim = arrival.claim;
        let app_for_metrics = Arc::clone(&app);
        let node = self.post.node();
        let unit = node.mint();
        let arrived = node.arrived();
        // The unit's generation, for a child it nests to be admitted against.
        self.frames_lock().insert(unit.get(), Arc::clone(&app));
        let _frame = UnitFrame {
            routes: self,
            unit: unit.get(),
        };
        let mut steps = DoorSteps::new(
            &live.facts,
            &live.pools,
            node.resolver(),
            app,
            Some(&*served.money),
            DoorCaller {
                principal: principal.clone(),
                key,
                open,
                arrived: arrived.secs(),
                records: Some(Arc::clone(served.kernel.units())),
                depth: nesting.as_ref().map_or(0, |n| n.depth),
                credential: credential.clone(),
            },
        );
        if let Some(n) = &nesting {
            steps = steps.under(n.parent.cell());
        }
        let far = DoorFar {
            egress: live.egress.as_deref(),
            shown: live.shown.as_ref(),
            steps: &steps,
            unit,
            credential,
            far: OnceLock::new(),
        };
        let units = served.driver.unit(&steps, &far, caller, arrival, 0);
        let money = Arc::clone(&served.money);
        let facts = live.facts.clone();
        let late: crate::root::linked::node::Late =
            Box::new(move || report_of(&money, unit, &facts));
        // THE UNIT'S REQUEST SPAN, as the previous release's forward opened one around the whole
        // walk (at the hot-path level, so the OTLP export carries it): the pool and the dialect the
        // request was read in are recorded once the plane has read it.
        let span = tracing::span!(
            busbar_kernel::observability::HOTPATH_LEVEL,
            "forward",
            plane = %served.instance,
            pool = tracing::field::Empty,
            ingress = tracing::field::Empty,
            request_id = tracing::field::Empty
        );
        let _taken = {
            use tracing::Instrument as _;
            node.drive_borrowed(
                unit,
                arrived,
                &principal,
                &self.post,
                &units,
                late,
                (self.pin)(),
                nesting.as_ref().map(|n| &n.parent),
            )
            .instrument(span.clone())
            .await
        };
        if let Some(decoded) = units.decoded() {
            if let Some(pool) = decoded.pool.as_ref() {
                span.record("pool", String::from_utf8_lossy(pool).as_ref());
            }
            if let Some(dialect) = served.dialects.get(decoded.dialect as usize) {
                span.record("ingress", *dialect);
            }
        }
        drop(span);
        let rendered = units.take_rendered();
        let status = rendered
            .as_ref()
            .map(|r| r.status)
            .or_else(|| caller.stated())
            .unwrap_or_else(|| refusal_status(ReasonCode::PlanePanic));
        served.money.settle_end(unit, status);
        // THE REQUEST FAMILIES of the plane serving the `pools` map (the flat card's plane), as the
        // previous release's `ingress::finish_inner` emitted them: for every request its dialect
        // read (decoded, or refused for its body; a path it does not serve, or a verb it does not
        // take, never reached a dialect), under the dialect it arrived in and the pool or model it
        // named ("unresolved" when it named none the configuration holds).
        if live.facts.plane.is_empty() {
            let decoded = units.decoded();
            let counted = decoded.is_some()
                || units
                    .declined_status()
                    .is_some_and(|s| s != 404 && s != 405);
            if counted {
                let dialect = decoded.as_ref().map_or_else(
                    || {
                        served
                            .snapshot
                            .claims
                            .get(claim as usize)
                            .map_or(0, |c| u32::from(c.refusal_dialect))
                    },
                    |d| d.dialect,
                );
                // A pool route is counted under the pool that served it: a budget downgrade's, as
                // 1.5.5 counted the effective pool (v1.5.5 ingress/dispatch.rs:206, :275).
                let served_pool = steps.routed().map(|(label, _)| label);
                let pool = served_pool
                    .filter(|label| !label.is_empty())
                    .map(String::into_bytes)
                    .or_else(|| decoded.and_then(|d| d.pool))
                    .map(|p| String::from_utf8_lossy(&p).into_owned())
                    .filter(|name| {
                        live.pools.pools().contains_key(name)
                            || live.pools.entries().iter().any(|e| e == name)
                    })
                    .unwrap_or_else(|| "unresolved".to_string());
                busbar_kernel::telemetry::model_request_finished(
                    &app_for_metrics,
                    served.dialects.get(dialect as usize).copied().unwrap_or(""),
                    &pool,
                    u16::try_from(status).unwrap_or(u16::MAX),
                    started.elapsed().as_secs_f64(),
                );
            }
        }
        rendered
    }
}

/// A nested unit's place: its parent, live on the node, and its depth.
#[cfg(linked_axis_node)]
struct Nesting {
    parent: crate::root::plane_node::Parent,
    depth: u32,
}

/// WHAT A DOOR UNIT CONSUMED, as the node's report (its one line, priced at the card pinned at its
/// door): the plane's last far-end-reported counts by class name (an estimate never bills; a fee
/// unit is no usage), whether it incurred its fee, and the key it was served under. `None` for a
/// unit whose money was never opened (an anonymous or refused unit): its line is the exit's.
#[cfg(linked_axis_node)]
fn report_of(
    money: &PlaneMoney,
    unit: busbar_contract::UnitKey,
    facts: &DoorFacts,
) -> Option<crate::root::linked::node::Reported> {
    let lane = money.serving(unit)?;
    let mut usage_units: BTreeMap<String, u64> = BTreeMap::new();
    let mut fee = 0u32;
    for u in money
        .last_counts(unit)
        .iter()
        .filter(|u| busbar_contract::abi::plane::units_bill(u.source))
    {
        if facts.fee_units.contains(&u.class) {
            fee = fee.max(u32::from(u.amount > 0));
            continue;
        }
        if let Some(name) = facts.classes.get(u.class as usize) {
            let n = usage_units.entry(name.clone()).or_insert(0);
            *n = n.saturating_add(u.amount);
        }
    }
    usage_units.retain(|_, n| *n > 0);
    Some((busbar_contract::billing::Usage { usage_units }, fee, lane))
}

/// A DOOR UNIT'S FAR END: the plane's egress walk over the connector (`EgressFarEnd`), started
/// once the unit's route is resolved, over the egress pool that route names; with no egress
/// composed, or no route, the walk is exhausted at once and nothing is dialled.
#[cfg(linked_axis_node)]
struct DoorFar<'d, 's> {
    egress: Option<&'d Egress>,
    /// What the hooks are shown of the members beside the walk.
    shown: Option<&'d crate::root::model_egress::ModelShown>,
    steps: &'d DoorSteps<'s>,
    unit: busbar_contract::UnitKey,
    /// The caller's verified credential, lent to the walk for a passthrough member alone.
    credential: Option<busbar_contract::redacted::Redacted<Vec<u8>>>,
    far: OnceLock<Option<EgressFarEnd<'d>>>,
}

#[cfg(linked_axis_node)]
impl<'d> DoorFar<'d, '_> {
    fn far(&self) -> Option<&EgressFarEnd<'d>> {
        self.far
            .get_or_init(|| {
                let egress = self.egress?;
                let routed = self.steps.routed()?;
                let pool = egress_pool(self.steps.plane(), &routed);
                let described = self.shown.and_then(|s| s.described.get(&pool).cloned());
                let mut far = egress.unit(UnitRoute {
                    unit: self.unit,
                    pool,
                    caller_credential: self.credential.clone(),
                    once: self.steps.once(),
                    wants_stream: self.steps.wants_stream(),
                    affinity: self.steps.affinity(),
                    ..UnitRoute::default()
                });
                if let Some(described) = described {
                    far = far.described(described);
                }
                if let Some(shown) = self.shown {
                    far = far.signals(Arc::clone(&shown.signals));
                }
                Some(far)
            })
            .as_ref()
    }
}

/// The walk's exhaustion terminal when no egress is composed: every path is spent.
#[cfg(linked_axis_node)]
fn spent() -> Pick {
    Pick::Exhausted {
        status: refusal_status(ReasonCode::NoDestination),
        retry_after: None,
        detail: busbar_kernel_egress::wire::DETAIL_OVERLOADED,
    }
}

#[cfg(linked_axis_node)]
impl FarEnd for DoorFar<'_, '_> {
    async fn member(&self, token: &Pass<Route>, attempt_no: u32) -> Pick {
        match self.far() {
            Some(far) => far.member(token, attempt_no).await,
            None => spent(),
        }
    }

    async fn send(&self, token: &Pass<Route>, request: OutboundRequest) -> bool {
        match self.far() {
            Some(far) => far.send(token, request).await,
            None => false,
        }
    }

    async fn next(&self, token: &Pass<Route>) -> Option<FarPiece> {
        match self.far() {
            Some(far) => far.next(token).await,
            None => None,
        }
    }

    async fn write(&self, token: &Pass<Route>, request: OutboundRequest) -> bool {
        match self.far() {
            Some(far) => far.write(token, request).await,
            None => false,
        }
    }

    // THE WALK'S FACTS FOR THE HOOK STAGE, as the unit's egress walk states them: its candidates,
    // what it has left and why it last failed, and the hooks' constraint handed to it. Without
    // these the kernel's hooks were shown no candidate and their constraint never reached the
    // walk on the door path.
    fn remaining(&self, token: &Pass<Route>) -> Option<usize> {
        self.far().and_then(|far| far.remaining(token))
    }

    fn failure(&self, token: &Pass<Route>) -> Option<&'static str> {
        self.far().and_then(|far| far.failure(token))
    }

    fn candidates(&self, token: &Pass<Route>) -> Option<busbar_kernel::plane_driver::Candidates> {
        self.far().and_then(|far| far.candidates(token))
    }

    fn constrain(&self, token: &Pass<Route>, constraint: busbar_kernel::plane_driver::Constraint) {
        if let Some(far) = self.far() {
            far.constrain(token, constraint);
        }
    }
}

// ── a session's caller side over today's upgrade (TRANSITIONAL) ──────────────────────────────────

/// The status a session's caller was answered with: the upgrade (`101 Switching Protocols`).
#[cfg(linked_axis_node)]
const SWITCHED: u32 = 101;

/// What a session arrival was admitted as: its plane, the generation serving it, and its caller.
#[cfg(linked_axis_node)]
struct SessionDoor {
    plane: usize,
    app: Arc<busbar_kernel::state::App>,
    principal: PrincipalId,
    key: Option<Arc<busbar_contract::records::VirtualKey>>,
    open: bool,
    /// The caller's verified credential, lent to a passthrough member alone.
    credential: Option<busbar_contract::redacted::Redacted<Vec<u8>>>,
}

/// THE CALLER'S SIDE OF A DUPLEX SESSION over today's hyper upgrade (K6's one `SessionCaller`;
/// ARCHITECT Q-L5B-SESSION-SERVE 2026-10-03, the `IngressCaller` pattern; TRANSITIONAL: deleted when
/// INBOUND-LISTEN's `accepted::Caller` serves, 1.6.0-TODO "TRANSITIONAL ROWS"). Its pieces are the
/// caller's messages as the core's bridge hands them over; every frame the plane writes toward the
/// caller is one message, text when the plane said so. The caller's close ends its reads; a write after
/// the socket went answers `false`.
#[cfg(linked_axis_node)]
struct PipeCaller {
    from: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    to: mpsc::Sender<busbar_kernel::plane_routes::SessionOut>,
}

#[cfg(linked_axis_node)]
impl CallerEnd for PipeCaller {
    /// The upgrade was the session's head: nothing more is stated.
    fn head(&self, _status: u32, _fields: HeadFields) {}

    async fn write(&self, bytes: &[u8]) -> bool {
        let out = busbar_kernel::plane_routes::SessionOut {
            bytes: bytes.to_vec(),
            text: false,
        };
        self.to.send(out).await.is_ok()
    }

    async fn write_text(&self, bytes: &[u8]) -> bool {
        let out = busbar_kernel::plane_routes::SessionOut {
            bytes: bytes.to_vec(),
            text: true,
        };
        self.to.send(out).await.is_ok()
    }
}

#[cfg(linked_axis_node)]
impl busbar_kernel::plane_driver::SessionCaller for PipeCaller {
    /// Cancel-safe: a receive dropped before it resolved loses no message.
    async fn read(&self) -> Option<Vec<u8>> {
        self.from.lock().await.recv().await
    }
}

// ── the driver's caller side over today's ingress ────────────────────────────────────────────────

/// THE CALLER'S SIDE OF A DRIVEN UNIT over today's hyper ingress (TRANSITIONAL: deleted when
/// INBOUND-LISTEN's `accepted::Caller` serves the data door, 1.6.0-TODO "TRANSITIONAL ROWS").
///
/// The head goes to the handler once; the bytes go into the response body through a channel of one
/// piece, so a `write` resolves only once the body has taken the piece before it (the caller's side
/// was writable). A body the server dropped (the caller went away) answers `false`.
///
/// A unit served as a DUPLEX SESSION (its `arrive` stated `ROUTE_SESSION`, ARCHITECT round 5
/// Q-L3B-K6-HTTP (a)) has this caller side as its session's caller leg: its read yields the
/// arrival's body once, then nothing until the response is dropped, and the long-lived response is
/// what the session writes.
#[derive(Debug)]
pub struct IngressCaller {
    head: Mutex<Option<oneshot::Sender<Head>>>,
    body: mpsc::Sender<Bytes>,
    /// The status the unit stated its head with; `0` before it did.
    stated: std::sync::atomic::AtomicU32,
    /// The arrival's body, until a session's caller leg has read it.
    arrived: Mutex<Option<Bytes>>,
}

/// A reply head: the status number and the head fields.
type Head = (u32, HeadFields);

/// The handler's end of an [`IngressCaller`]: the reply, once the unit states its head.
#[derive(Debug)]
pub struct IngressReply {
    head: oneshot::Receiver<Head>,
    body: mpsc::Receiver<Bytes>,
    /// The answer's trailers, where a framer renders a close after its body (ARCHITECT 4l).
    trailers: Option<oneshot::Receiver<axum::http::HeaderMap>>,
}

impl IngressCaller {
    /// A caller side and the reply it feeds.
    #[must_use]
    pub fn new() -> (Self, IngressReply) {
        Self::arriving(Bytes::new())
    }

    /// A caller side whose request arrived with `body`, and the reply it feeds.
    #[must_use]
    pub fn arriving(body: Bytes) -> (Self, IngressReply) {
        let (head_tx, head) = oneshot::channel();
        let (body_tx, reply_body) = mpsc::channel(1);
        let caller = IngressCaller {
            head: Mutex::new(Some(head_tx)),
            body: body_tx,
            stated: std::sync::atomic::AtomicU32::new(0),
            arrived: Mutex::new(Some(body)),
        };
        (
            caller,
            IngressReply {
                head,
                body: reply_body,
                trailers: None,
            },
        )
    }

    /// The status the unit stated its head with, once it did.
    #[must_use]
    pub fn stated(&self) -> Option<u32> {
        Some(self.stated.load(std::sync::atomic::Ordering::Acquire)).filter(|s| *s != 0)
    }
}

/// A caller side that knows the status its unit stated its head with.
pub(crate) trait Stated {
    /// The status, once the unit stated its head.
    fn stated(&self) -> Option<u32>;
}

impl Stated for IngressCaller {
    fn stated(&self) -> Option<u32> {
        IngressCaller::stated(self)
    }
}

impl CallerEnd for IngressCaller {
    fn head(&self, status: u32, fields: HeadFields) {
        self.stated
            .store(status, std::sync::atomic::Ordering::Release);
        let sender = self
            .head
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(sender) = sender {
            // A handler that went away takes no head; its body's `write` answers `false`.
            let _gone = sender.send((status, fields));
        }
    }

    async fn write(&self, bytes: &[u8]) -> bool {
        self.body.send(Bytes::copy_from_slice(bytes)).await.is_ok()
    }
}

impl SessionCaller for IngressCaller {
    /// The arrival's body, once (taken when the read is first polled, so a read dropped unresolved
    /// loses nothing); then nothing until the response is dropped, when the caller's side ends.
    async fn read(&self) -> Option<Vec<u8>> {
        let first = self
            .arrived
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(body) = first {
            return Some(body.to_vec());
        }
        self.body.closed().await;
        None
    }
}

impl IngressReply {
    /// The response, once the unit has stated its head; `None` when the unit ended without one.
    /// A status the wire cannot carry is the plane's fault, answered as the driver answers a
    /// plane fault; a field the wire cannot carry is not sent.
    pub async fn response(self) -> Option<Response> {
        let head = self.head.await.ok()?;
        Some(stated(
            head,
            Body::new(ReplyBody(self.body, None, self.trailers)),
        ))
    }

    /// The same reply, its body followed by the trailers `trailers` delivers (a framer's close).
    #[must_use]
    pub fn with_trailers(mut self, trailers: oneshot::Receiver<axum::http::HeaderMap>) -> Self {
        self.trailers = Some(trailers);
        self
    }

    /// THE UNIT, SERVED: `unit` runs here until it states its head, then inside the response's
    /// body as the body is read, so a caller that goes away drops it (the driver's client-drop
    /// path). A unit that ends with no head answers what it rendered (a refusal or failure before
    /// any byte), or the driver's plane-fault status when it rendered nothing.
    pub async fn answer(self, unit: DrivenUnit) -> Response {
        self.answer_with(unit, |rendered| match rendered {
            Some(r) => stated((r.status, r.fields), Body::from(r.body)),
            None => stated(
                (refusal_status(ReasonCode::PlanePanic), Vec::new()),
                Body::empty(),
            ),
        })
        .await
    }

    /// [`IngressReply::answer`], a unit that ends with no head answered by `unrendered` from what
    /// it rendered (a framed stream's framer closes it, ARCHITECT 4l).
    pub async fn answer_with(
        self,
        mut unit: DrivenUnit,
        unrendered: impl FnOnce(Option<Rendered>) -> Response,
    ) -> Response {
        let IngressReply {
            mut head,
            body,
            trailers,
        } = self;
        let first = tokio::select! {
            biased;
            h = &mut head => Ok(h.ok()),
            rendered = &mut unit => Err(rendered),
        };
        let rendered = match first {
            // A WHOLE ANSWER goes out whole: an answer whose head states its length (one the plane
            // rendered in full) is collected to its end and sent under the length of what was
            // written, as the previous release sent a buffered answer; any other answer goes out
            // piece by piece as the unit writes it.
            Ok(Some(h)) if whole_answer(&h.1) => {
                let whole = collect(body, unit).await;
                return stated(unlengthed(h), Body::from(whole));
            }
            Ok(Some(h)) => return stated(h, Body::new(ReplyBody(body, Some(unit), trailers))),
            Ok(None) => unit.await,
            Err(rendered) => match head.try_recv() {
                // The unit ended in the poll that stated its head: a whole answer is every piece it
                // wrote, sent under its length.
                Ok(h) if whole_answer(&h.1) => {
                    let mut body = body;
                    let mut whole = Vec::new();
                    while let Ok(bytes) = body.try_recv() {
                        whole.extend_from_slice(&bytes);
                    }
                    return stated(unlengthed(h), Body::from(whole));
                }
                Ok(h) => return stated(h, Body::new(ReplyBody(body, None, trailers))),
                Err(_) => rendered,
            },
        };
        unrendered(rendered)
    }
}

/// Who a door unit serves: the principal the auth gate verified, its governance key, and its
/// verified credential (lent for a passthrough member's outbound auth call alone).
#[cfg(linked_axis_node)]
type UnitCaller = (
    PrincipalId,
    Option<Arc<busbar_contract::records::VirtualKey>>,
    Option<busbar_contract::redacted::Redacted<Vec<u8>>>,
);

/// Whether a reply head is a WHOLE answer's: it states its length and is no event stream (SSE, or
/// the AWS event-stream framing, which the previous release relayed piece by piece).
fn whole_answer(fields: &HeadFields) -> bool {
    let named = |field: &[u8]| {
        fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(field))
            .map(|(_, value)| String::from_utf8_lossy(value).to_ascii_lowercase())
    };
    named(b"content-length").is_some()
        && !named(b"content-type").is_some_and(|v| {
            v.starts_with("text/event-stream")
                || v.starts_with("application/vnd.amazon.eventstream")
        })
}

/// A whole answer's head without its stated length: the response states the length of what was
/// written.
fn unlengthed((status, mut fields): Head) -> Head {
    fields.retain(|(name, _)| !name.eq_ignore_ascii_case(b"content-length"));
    (status, fields)
}

/// Every piece the unit writes until it ends, the unit driven meanwhile (its writes wait on this
/// side), then whatever it wrote last.
async fn collect(mut body: mpsc::Receiver<Bytes>, mut unit: DrivenUnit) -> Vec<u8> {
    let mut whole = Vec::new();
    loop {
        tokio::select! {
            biased;
            piece = body.recv() => match piece {
                Some(bytes) => whole.extend_from_slice(&bytes),
                None => {
                    let _ = unit.await;
                    break;
                }
            },
            _ = &mut unit => {
                while let Ok(bytes) = body.try_recv() {
                    whole.extend_from_slice(&bytes);
                }
                break;
            }
        }
    }
    whole
}

/// A unit the data door drives: what it rendered for its caller when it ended before any byte.
pub type DrivenUnit = std::pin::Pin<Box<dyn std::future::Future<Output = Option<Rendered>> + Send>>;

/// A response under a stated head: a status the wire cannot carry is the plane's fault, answered as
/// the driver answers a plane fault; a field the wire cannot carry is not sent.
fn stated((status, fields): Head, body: Body) -> Response {
    let status = [status, refusal_status(ReasonCode::PlanePanic)]
        .into_iter()
        .find_map(|s| StatusCode::from_u16(u16::try_from(s).ok()?).ok())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    for (name, value) in fields {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(&name),
            HeaderValue::from_bytes(&value),
        ) {
            headers.append(name, value);
        }
    }
    response
}

/// The response body: the pieces the unit writes, in order, until its caller side is dropped; the
/// unit itself, driven as the body is read, while it runs; and the trailers a framer's close
/// rendered, after the last piece, where the answer has them.
struct ReplyBody(
    mpsc::Receiver<Bytes>,
    Option<DrivenUnit>,
    Option<oneshot::Receiver<axum::http::HeaderMap>>,
);

impl http_body::Body for ReplyBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(unit) = &mut this.1 {
            if unit.as_mut().poll(cx).is_ready() {
                this.1 = None;
            }
        }
        match this.0.poll_recv(cx) {
            std::task::Poll::Ready(Some(bytes)) => {
                std::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes))))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(None) => {
                let Some(trailers) = &mut this.2 else {
                    return std::task::Poll::Ready(None);
                };
                match std::future::Future::poll(std::pin::Pin::new(trailers), cx) {
                    std::task::Poll::Pending => std::task::Poll::Pending,
                    std::task::Poll::Ready(sent) => {
                        this.2 = None;
                        std::task::Poll::Ready(
                            sent.ok().map(|map| Ok(http_body::Frame::trailers(map))),
                        )
                    }
                }
            }
        }
    }
}

#[cfg(linked_axis_node)]
#[path = "serve_framed.rs"]
mod serve_framed;

#[cfg(test)]
#[path = "tests/serve.rs"]
mod tests;

// `serve_planes.rs` uses `crate::root::plane_node`, compiled only when a linked plane rides the
// `node` axis (the generated `linked_axis_node` cfg, root/mod.rs); its only consumers are the
// `linked_axis_node`-gated `money_tests`/`door_tests`, so gating it to the same cfg loses no
// coverage under the default node-bearing build and lets the bin test build under
// `--no-default-features`, where no plane rides the node axis.
#[cfg(all(test, linked_axis_node))]
#[path = "tests/serve_planes.rs"]
mod planes_tests;

// The door test file: the decisions door's served route, and the capability cells of the door
// serving the `pools` map under the fold switch.
#[cfg(all(
    test,
    linked_axis_node,
    any(feature = "plane-decisions", linked_fold_on_driver)
))]
#[path = "tests/serve_door.rs"]
mod door_tests;

// The legacy engine's end-to-end tests, held to the door serving the `pools` map (U11).
#[cfg(all(test, linked_fold_on_driver, linked_axis_node))]
#[path = "tests/serve_door_ported.rs"]
mod door_ported_tests;

#[cfg(all(test, linked_axis_node))]
#[path = "tests/serve_money.rs"]
mod money_tests;

#[cfg(all(test, linked_fold_on_driver, linked_axis_node))]
#[path = "tests/serve_hook_seats.rs"]
mod hook_seat_tests;

#[cfg(all(test, linked_fold_on_driver, linked_axis_node))]
#[path = "tests/serve_door_hooks_ported.rs"]
mod door_hooks_ported_tests;

// The far end's answer on the door, ported from the legacy engine's tests.
#[cfg(all(test, linked_fold_on_driver, linked_axis_node))]
#[path = "tests/serve_door_reply_ported.rs"]
mod door_reply_ported_tests;

// The previous release's engine tests whose behaviour the kernel owns, on the door serving the
// `pools` map, where a kernel unit test cannot express them.
#[cfg(all(test, linked_fold_on_driver, linked_axis_node))]
#[path = "tests/serve_door_kernel_ported.rs"]
mod door_kernel_ported_tests;

// The exchange cases of the retired engine crate, served through the door (the U11 port).
#[cfg(all(test, linked_fold_on_driver, linked_axis_node))]
#[path = "tests/serve_door_exchange_ported.rs"]
mod door_exchange_ported_tests;

#[cfg(all(test, linked_axis_node))]
#[path = "tests/serve_framed.rs"]
mod framed_tests;
