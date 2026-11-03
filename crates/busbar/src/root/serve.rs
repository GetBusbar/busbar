// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome as AbiOutcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};
use busbar_contract::caps::{OpClassId, ReasonCode};
use busbar_contract::plane::{declares_record_kind, PlaneDeclaration};
use busbar_contract::plane_calls::PlaneCalls;
use busbar_contract::services::{
    Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Stored,
};
use busbar_kernel::host_records::QUEUE_CAP;
use busbar_kernel::host_services::{BlockingPool, DestJudge, KernelServices, SignKey};
use busbar_kernel::plane_driver::serve::{ServeRoute, ServeTable, ServeTables};
use busbar_kernel::plane_driver::{
    refusal_status, BufferCaps, CallerEnd, DriverConfig, Egress, HeadFields, MoneySeam,
    PlaneDriver, PlaneMoney, Rendered, SessionCaller,
};
use busbar_kernel::store::plane_view::KIND_DEMOTION;
use busbar_kernel::trust::DemotionRecord;
use tokio::sync::{mpsc, oneshot};

use crate::root::boot::DoorPlane;
use crate::root::door_steps::{door_facts, DoorFacts, DoorPools};
use crate::root::loader::dispatch::kinds::plane::OwnedSnapshot;
use crate::root::loader::dispatch::plane_calls::PlaneInstance;
use crate::root::loader::dispatch::services::ServicesSlot;

use crate::root::door_steps::{egress_pool, DoorCaller, DoorSteps};
use crate::root::loader::dispatch::{in_head, out_head, Dispatcher, Frame};
use busbar_contract::abi::host::conn::connector::NEVER_KEPT;
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_contract::abi::plane::{
    CLAIM_ENTRY, CLAIM_EXACT, CLAIM_OPEN, CLAIM_PATTERN, CLAIM_RAW_AFFIX,
};
use busbar_contract::auth::AuthPrincipal;
use busbar_contract::caps::{Pass, PrincipalId, Route};
use busbar_kernel::observability::arrival::EntrySpans;
use busbar_kernel::plane_driver::{
    Arrival, EgressFarEnd, FarEnd, FarPiece, OutboundRequest, Pick, RoutedScope, UnitRoute,
};
use busbar_kernel::plane_routes::{
    PlaneRefusalSpec, PlaneReqCtx, PlaneRouteFuture, PlaneRouteSpec,
};

pub const DEFAULT_EGRESS_CLASS: u32 = 0;

#[must_use]
pub fn kernel_services(dest: Arc<dyn DestJudge>) -> KernelServices {
    KernelServices::new()
        .with_dest_judge(dest)
        .with_disk_lane(crate::root::linked::disk_lane())
}

pub fn compose(
    dest: Arc<dyn DestJudge>,
    late: &LateServices,
    credentials: crate::root::credentials::AppCredentials,
) {
    let kernel = Arc::new(kernel_services(dest).with_credentials(Arc::new(credentials)));
    if late
        .install_kernel(Arc::clone(&kernel), kernel as Arc<dyn HostServices>)
        .is_err()
    {
        tracing::debug!("the kernel's host services were already installed");
    }
}

pub struct LiveTickets(pub std::sync::Weak<busbar_kernel::state::AppHandle>);

impl busbar_kernel::host_services::TicketPress for LiveTickets {
    fn mint(
        &self,
        key_id: &str,
        prefix: &str,
        ttl_secs: u64,
        record: &[u8],
        now: u64,
    ) -> Result<(String, u64), &'static str> {
        use busbar_kernel::governance::TicketRefusal;
        let app = self
            .0
            .upgrade()
            .ok_or(TicketRefusal::NoSigner.reason())?
            .load();
        let gov = app
            .governance
            .as_deref()
            .ok_or(TicketRefusal::NoSigner.reason())?;
        gov.mint_ticket(
            key_id,
            prefix,
            ttl_secs,
            app.mint_policy.block_max_ttl_secs,
            record,
            now,
        )
        .map_err(TicketRefusal::reason)
    }
}

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
        let cadence = Arc::clone(&kernel);
        tokio::spawn(async move { cadence.flushes().await });
    }
    if let Some(signer) = signer {
        kernel.attach_signer(signer);
    }

    if let Some(gov) = records {
        if let Some(calls) = gov.store_calls() {
            kernel.attach_records(Arc::new(busbar_kernel::host_records::StoreRows(calls)));
        }
    }
    if let Some(owner) = demotion_owner(planes) {
        kernel.attach_demotions(Arc::clone(demotions), owner);
    }
}

pub const RECORD_DRAIN: std::time::Duration =
    std::time::Duration::from_secs(5 * busbar_kernel::host_records::FLUSH_INTERVAL.as_secs());

pub async fn drain_records(late: &LateServices, deadline: std::time::Duration) -> bool {
    let Some(kernel) = late.kernel() else {
        return true;
    };
    tokio::task::spawn_blocking(move || kernel.drain(deadline))
        .await
        .unwrap_or(false)
}

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

pub struct LateServices {
    slot: Arc<ServicesSlot>,

    kernel: OnceLock<Arc<KernelServices>>,
}

/// Why [`LateServices::install`] would not take a second set of services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlreadyInstalled;

pub const NOT_INSTALLED: &str = "the kernel's host services are not installed yet";

impl LateServices {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(LateServices {
            slot: ServicesSlot::late(Arc::new(NotInstalled(KernelServices::new()))),
            kernel: OnceLock::new(),
        })
    }

    #[must_use]
    pub fn slot(&self) -> Arc<ServicesSlot> {
        Arc::clone(&self.slot)
    }

    pub fn install(&self, services: Arc<dyn HostServices>) -> Result<(), AlreadyInstalled> {
        if self.slot.install(services) {
            Ok(())
        } else {
            Err(AlreadyInstalled)
        }
    }

    pub fn install_kernel(
        &self,
        kernel: Arc<KernelServices>,
        services: Arc<dyn HostServices>,
    ) -> Result<(), AlreadyInstalled> {
        self.install(services)?;
        self.kernel.set(kernel).map_err(|_| AlreadyInstalled)
    }

    #[must_use]
    pub fn kernel(&self) -> Option<Arc<KernelServices>> {
        self.kernel.get().cloned()
    }

    #[must_use]
    pub fn is_installed(&self) -> bool {
        self.slot.is_installed()
    }

    #[cfg(test)]
    pub(crate) fn served(&self) -> Arc<dyn HostServices> {
        Arc::clone(self.slot.get().expect("a late slot always serves"))
    }
}

struct NotInstalled(KernelServices);

fn not_installed() -> Stored {
    Stored::refused(NOT_INSTALLED)
}

impl HostServices for NotInstalled {
    fn now(&self) -> Reading {
        self.0.now()
    }

    fn dest_judge(&self, _: &str, _: u32, _: u32, _: Option<Later>) -> Ran {
        Ran::Now(not_installed())
    }

    fn records_get(&self, _: &Caller, _: &str, _: &[u8], _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn records_list(&self, _: &Caller, _: RecordsList, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn records_claim(&self, _: &Caller, _: &str, _: &[u8], _: u64, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
        not_installed()
    }

    fn trust_sight(&self, _: &Caller, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn trust_unreached(&self, _: &Caller, _: &str) -> Stored {
        not_installed()
    }

    fn trust_decide(
        &self,
        _: &Caller,
        _: busbar_contract::services::TrustKeyRef<'_>,
        _: Option<&str>,
        _: bool,
    ) -> Stored {
        not_installed()
    }

    fn trust_state(&self, _: &Caller, _: &str) -> Stored {
        not_installed()
    }

    fn trust_sight_item(&self, _: &Caller, _: &str, _: &str, _: &str) -> Stored {
        not_installed()
    }

    fn trust_serves(&self, _: &Caller, _: &str, _: Option<&str>, _: Option<&str>) -> Stored {
        not_installed()
    }

    fn trust_due(&self, _: &Caller) -> Stored {
        not_installed()
    }

    fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
        not_installed()
    }

    fn entitlement_check(&self, _: &Caller, _: Option<u64>, _: &str) -> Stored {
        not_installed()
    }

    fn random_fill(&self, _: u64) -> Stored {
        not_installed()
    }

    fn session_emit(&self, _: &Caller, _: u64, _: &[u8]) -> Stored {
        not_installed()
    }

    fn ticket_mint(&self, _: &Caller, _: Option<u64>, _: u64, _: &[u8]) -> Stored {
        not_installed()
    }

    fn ticket_take(&self, _: &Caller, _: Option<u64>) -> Stored {
        not_installed()
    }

    fn records_secret(&self, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn unit_nest(&self, _: &Caller, _: Option<u64>, _: NestAsk, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn work_open(&self, _: &Caller, _: Option<u64>, _: &str, _: &[u8], _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn work_find(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn work_settle(&self, _: &Caller, _: Option<u64>, _: u64, _: &[u8], _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn work_resume(&self, _: &Caller, _: Option<u64>, _: u64, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn disk_append(&self, _: &DiskDest, _: Vec<u8>, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn verify_lookup(&self, _: &Caller, _: &[u8], _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn verify_store(&self, _: &Caller, _: &[u8], _: &[u8], _: u64) -> Stored {
        not_installed()
    }

    fn content_scan(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn hook_call(&self, _: &Caller, _: Option<u64>, _: HookAsk, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn snapshot_read(&self, _: &Caller, _: u32) -> busbar_contract::services::Snapshot {
        busbar_contract::services::Snapshot::Refused(NOT_INSTALLED)
    }
}

/// ONE DOOR PLANE, COMPOSED: its instance, the driver the
/// kernel serves it through, the snapshot its `open` published (its claims and admin routes), and
/// what its units are served by: its tail's facts, the pools its section states, its money steps
/// and its egress.
#[derive(Clone)]
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

// Egress snapshots can outlive their DoorLive (for example, a retained probe).
// Keep the exact loader generation with the connection table they retain.
struct BoundConns {
    inner: Arc<dyn busbar_contract::conn::PollConns>,
    _binding: crate::root::loader::dispatch::plugin::ConnectionBinding,
}

impl busbar_contract::conn::Conns for BoundConns {
    fn open(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        self.inner.open(caller, need, desc)
    }
    fn open_with_security(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
        secure: bool,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        self.inner.open_with_security(caller, need, desc, secure)
    }
    fn write(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        self.inner.write(caller, conn, bytes, end, text)
    }
    fn read(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        ticket: busbar_contract::conn::Ticket,
        buf: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        self.inner.read(caller, conn, ticket, buf)
    }
    fn wait(
        &self,
        caller: busbar_contract::conn::InstanceId,
        set: &[busbar_contract::conn::ConnId],
        ticket: busbar_contract::conn::Ticket,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        self.inner.wait(caller, set, ticket)
    }
    fn facts(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, busbar_contract::conn::ConnError> {
        self.inner.facts(caller, conn)
    }
    fn close(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.inner.close(caller, conn)
    }
}
impl busbar_contract::conn::PollConns for BoundConns {
    fn poll_read(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError>>
    {
        self.inner.poll_read(caller, conn, cx, buf)
    }
    fn anchor(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        member: &str,
        target: &str,
        anchors: &busbar_contract::transport::trust::Anchors,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.inner.anchor(owner, need, member, target, anchors)
    }
    fn head_defaults(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        target: &str,
    ) -> busbar_contract::conn::HeadDefaults {
        self.inner.head_defaults(owner, need, target)
    }
    fn seal_reach(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        member: &str,
        target: &str,
        reach: bool,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.inner.seal_reach(owner, need, member, target, reach)
    }
}

fn bound_conns(
    binding: crate::root::loader::dispatch::plugin::ConnectionBinding,
    inner: Arc<dyn busbar_contract::conn::PollConns>,
) -> Arc<dyn busbar_contract::conn::PollConns> {
    Arc::new(BoundConns {
        inner,
        _binding: binding,
    })
}

pub struct DoorLive {
    pub section: serde_yaml::Value,

    pub generation: u64,

    pub pools: DoorPools,

    pub egress: Option<Arc<Egress>>,

    pub facts: DoorFacts,

    pub probes: Option<Arc<busbar_kernel::plane_driver::PlaneProbes>>,

    pub shown: Option<crate::root::model_egress::ModelShown>,
}

pub struct ApplyReach {
    providers: BTreeMap<String, crate::root::door_steps::ProviderRoute>,
    auths: Arc<crate::root::door_steps::OutboundAuths>,
    conns: Arc<dyn busbar_contract::conn::PollConns>,
    journal: Arc<dyn busbar_kernel_egress::ports::Journal>,
    stream_ceiling_secs: u64,

    catalog: Option<std::collections::HashMap<String, busbar_contract::config::ModelCfg>>,
    upgrades: Vec<&'static str>,
}

pub struct DoorApply {
    plugin: DoorPlane,
    served_facts: crate::root::loader::dispatch::kinds::plane::ServedFacts,
    facts: DoorFacts,
    reach: Option<ApplyReach>,
    live: std::sync::RwLock<Arc<DoorLive>>,

    driver: Arc<PlaneDriver>,

    probe_schedule: Arc<busbar_kernel::probe::ProbeSchedule>,

    scope_kinds: Vec<&'static str>,

    clock: Arc<dyn busbar_kernel_egress::ports::Clock>,

    units: Arc<busbar_kernel::host_units::UnitRecords>,
}

impl DoorApply {
    #[must_use]
    pub fn current(&self) -> Arc<DoorLive> {
        Arc::clone(
            &self
                .live
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub fn apply(&self, app: &busbar_kernel::state::App) {
        if self.served_facts.section == busbar_contract::section::RESERVED_POOLS_KEY {
            return;
        }
        let now = self.current();

        let section = applied_section(app, &self.facts.plane, self.served_facts.section, &now);

        let config = app
            .config_projection
            .as_ref()
            .and_then(|p| p.downcast_ref::<crate::root::door_steps::DoorConfig>());
        let owned = config
            .map(|c| owned_sections(&self.served_facts, &c.sections))
            .unwrap_or_default();

        let handed = match config {
            Some(c) if !section.is_null() => settings_of(&self.served_facts, &section, &c.sections),
            _ => section.clone(),
        };

        let scope = busbar_contract::config_time::ConfigScope::config_time();
        match self.refreshed(
            &section,
            &handed,
            &owned,
            now.generation + 1,
            Arc::clone(&app.secret_resolver) as Arc<dyn busbar_contract::secret::SecretResolve>,
            &scope,
        ) {
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
            Err(e) => {
                tracing::warn!(
                    plane = self.facts.plane.as_str(),
                    error = %e,
                    "door plane kept its generation across a config apply"
                );

                crate::root::loader::dispatch::kinds::plane::retire_door(
                    &self.plugin,
                    now.generation + 1,
                );
            }
        }
    }

    fn refreshed(
        &self,
        section: &serde_yaml::Value,
        handed: &serde_yaml::Value,
        owned: &serde_json::Map<String, serde_json::Value>,
        generation: u64,
        secrets: Arc<dyn busbar_contract::secret::SecretResolve>,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<DoorLive, String> {
        crate::root::door_steps::member_tls_refusal(&self.served_facts, section)?;
        let admission = self
            .driver
            .prepare_section((self.served_facts.section, section))?;
        let settings = if section.is_null() {
            Vec::new()
        } else {
            handed_settings(settings_path(&self.served_facts), handed)?
        };
        crate::root::loader::dispatch::kinds::plane::refresh_door(
            &self.plugin,
            &settings,
            &owned_bytes(owned)?,
            generation,
        )?;
        let binding = self.plugin.connection_binding();
        let (table, catalog_entry) = routes_of(
            section,
            self.reach.as_ref().and_then(|r| r.catalog.as_ref()),
        );
        let pools = DoorPools::of(&table, self.served_facts.section)
            .map_err(|e| format!("{}: {e}", self.facts.plane.as_str()))?;
        let mut facts = self.facts.clone();
        seal_secondary_scopes(
            &mut facts,
            &self.scope_kinds,
            &pools,
            catalog_entry.as_deref(),
        );
        let mut fetches = None;
        let egress = match &self.reach {
            Some(r) => {
                let reach = crate::root::door_steps::DoorReach {
                    providers: &r.providers,
                    secrets,
                    auths: Arc::clone(&r.auths),
                    conns: Arc::clone(&r.conns),
                    stream_ceiling_secs: r.stream_ceiling_secs,
                    catalog: r.catalog.as_ref(),
                    upgrades: r.upgrades.clone(),
                    models: None,
                };
                let routes = crate::root::door_steps::member_routes(
                    &table,
                    &pools,
                    &self.served_facts,
                    &reach,
                    scope,
                )?;
                let egress = crate::root::door_steps::compose_egress(
                    &facts,
                    &pools,
                    binding.owner(),
                    bound_conns(binding.clone(), Arc::clone(&r.conns)),
                    &routes,
                    Arc::clone(&r.journal),
                    Arc::clone(&self.clock),
                    r.stream_ceiling_secs,
                )?;

                fetches = Some(routes);
                Some(Arc::new(egress))
            }
            None => None,
        };
        admission.commit()?;
        if let Some(routes) = fetches {
            bind_fetches(
                &self.plugin,
                binding.owner(),
                &self.served_facts,
                &routes,
                &self.units,
            );
        }
        Ok(DoorLive {
            section: section.clone(),
            generation,
            pools,
            egress,
            facts,
            probes: None,
            shown: None,
        })
    }
}

#[must_use]
pub fn applied_section(
    app: &busbar_kernel::state::App,
    plane: &str,
    section_key: &str,
    now: &DoorLive,
) -> serde_yaml::Value {
    let Some(slot) = app
        .plane_slots
        .get(plane)
        .and_then(|s| s.downcast_ref::<busbar_kernel::plane_driver::door::DoorSlot>())
    else {
        return now.section.clone();
    };

    if let Some(own) = app.plane_pools(plane) {
        let mut section = slot.section.value.clone();
        pools_into(&mut section, own);
        return section;
    }
    section_with_pools(section_key, &slot.section.value, &installed_door_pools(app))
}

/// EVERY SERVED DOOR PLANE'S APPLY, kept when the planes move into the data routes, for the
/// handle's appliers ([`busbar_kernel::state::AppHandle::on_apply`]).
#[derive(Clone, Default)]
pub struct DoorAppliers(Vec<Arc<DoorApply>>);

impl DoorAppliers {
    pub fn apply(&self, app: &busbar_kernel::state::App) {
        for plane in &self.0 {
            plane.apply(app);
        }
    }

    pub fn refresh_models(
        &self,
        sections: &BTreeMap<&'static str, serde_yaml::Value>,
        egress: &DoorEgress<'_>,
    ) {
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        for p in &self.0 {
            let facts = &p.served_facts;
            if facts.section != busbar_contract::section::RESERVED_POOLS_KEY {
                continue;
            }
            let Some(section) = sections.get(facts.section) else {
                continue;
            };
            let name = p.plugin.name();

            let settings = match busbar_kernel::config::filled::plane_bound_bytes(
                settings_path(facts),
                &settings_of(facts, section, sections),
            ) {
                Ok(settings) => settings,
                Err(e) => {
                    tracing::error!(plane = name, error = %e, "door plane's new configuration is not JSON; it keeps serving the previous one");
                    continue;
                }
            };
            let walked = walked_section(facts, section, sections);
            if let Err(e) = crate::root::door_steps::member_tls_refusal(facts, &walked) {
                tracing::error!(plane = name, error = %e, "door plane's TLS configuration is invalid; it keeps serving the previous one");
                continue;
            }
            let now = p.current();
            let next = now.generation + 1;
            let owned = match owned_bytes(&owned_sections(facts, sections)) {
                Ok(owned) => owned,
                Err(e) => {
                    tracing::error!(plane = name, error = %e, "door plane's new configuration is not JSON; it keeps serving the previous one");
                    continue;
                }
            };
            if let Err(e) = crate::root::loader::dispatch::kinds::plane::refresh_door(
                &p.plugin, &settings, &owned, next,
            ) {
                tracing::error!(plane = name, error = %e, "door plane did not refresh onto the new configuration; it keeps serving the previous one");

                crate::root::loader::dispatch::kinds::plane::retire_door(&p.plugin, next);
                continue;
            }
            match seal_live(
                name,
                &p.plugin,
                facts,
                &p.scope_kinds,
                &walked,
                Some(egress),
                &p.clock,
                next,
                p.facts.bench_below_trip_threshold,
                &scope,
                &p.units,
            ) {
                Ok(mut live) => {
                    arm_probes(&p.driver, facts, &mut live, Some(egress), &p.probe_schedule);
                    *p.live
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(live);
                }
                Err(e) => {
                    tracing::error!(plane = name, error = %e, "door plane's new configuration did not seal; it keeps serving the previous one");

                    crate::root::loader::dispatch::kinds::plane::retire_door(&p.plugin, next);
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
#[derive(Debug, Default, Clone)]
pub struct Served {
    /// The process's shared nested-unit registry, also lent to the line carrier at boot.
    nests: Option<NestRoutes>,
    /// In the order the planes were bound.
    pub planes: Vec<ServedPlane>,
    /// The posting site the planes' money steps post an abandoned end to, and the units' facts are
    /// opened on while they run: the process's one node's.
    pub post: Option<Arc<crate::root::plane_node::NodeEndPost>>,
    /// The framer that answers a claim, by its name: what frames a stream that arrived on a claim
    /// another framer than the data listener's own answers. `None` = the process's
    /// one connector's.
    pub framers: Option<StreamFramers>,
    /// THE CLAIM DOORS, by the claim their datagram framer answers: the datagram port each one's
    /// inbound need binds ([`serve_datagram::ClaimDoor`]). Empty = no datagram claim is served.
    pub claim_doors: serve_datagram::ClaimDoors,
    /// THE PUBLISHED INSTANCES' ADMIN TABLE these planes were published into: the generation's
    /// (`App::serve_tables`) the composition was lent, held here for the data listener's public
    /// mount ([`public_routes`]).
    pub tables: ServeTables,
}

/// The framer that answers a claim, by its name (`Connector::framer_for`).
#[derive(Clone)]
pub struct StreamFramers(pub Arc<FramerFor>);

pub type FramerFor =
    dyn Fn(&str) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>> + Send + Sync;

impl std::fmt::Debug for StreamFramers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamFramers")
    }
}

impl Served {
    #[must_use]
    pub fn appliers(&self) -> DoorAppliers {
        DoorAppliers(self.planes.iter().map(|p| Arc::clone(&p.live)).collect())
    }

    #[must_use]
    pub fn need_trust(&self) -> Vec<&'static str> {
        self.planes
            .iter()
            .flat_map(|p| p.live.served_facts.need_trust.iter().copied())
            .collect()
    }

    #[must_use]
    pub fn member_tls_sections(&self) -> Vec<&'static str> {
        self.planes
            .iter()
            .filter(|plane| {
                plane
                    .live
                    .served_facts
                    .need_trust
                    .iter()
                    .any(|path| busbar_contract::section::member_target(path) == Some("tls"))
            })
            .map(|plane| plane.live.served_facts.section)
            .collect()
    }

    #[must_use]
    pub fn unopened(&self, doors: &[(String, DoorPlane)]) -> Vec<&'static str> {
        doors
            .iter()
            .filter(|(instance, _)| !self.planes.iter().any(|p| p.instance == *instance))
            .map(|(_, plugin)| plugin.served())
            .filter(|served| !served.fallback)
            .map(|served| served.section)
            .collect()
    }
}

impl Served {
    pub fn spawn_ticks(&self) {
        for p in &self.planes {
            let driver = Arc::clone(&p.driver);
            tokio::spawn(async move { driver.ticks().await });
            let driver = Arc::clone(&p.driver);
            tokio::spawn(async move { driver.drives().await });
        }

        if let Some(post) = &self.post {
            let lease = LeaseTick {
                node: Arc::clone(post.node()),
            };
            tokio::spawn(lease.ticks());
        }
    }
}

struct LeaseTick {
    node: Arc<crate::root::plane_node::Node>,
}

impl LeaseTick {
    fn tick(&self) {
        if let Some(lane) = self.node.journal_lane() {
            lane.refresh_held_lease();
        }
        self.node.retry_held_journal();
    }

    async fn ticks(self) {
        let every = busbar_kernel::host_records::FLUSH_INTERVAL;
        let mut at = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        at.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let this = Arc::new(self);
        loop {
            at.tick().await;
            let tick = Arc::clone(&this);
            let _refreshed = tokio::task::spawn_blocking(move || tick.tick()).await;
        }
    }
}

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
    tables: &ServeTables,
) -> Result<Served, String> {
    compose_served_checked(
        gov,
        doors,
        dispatcher,
        late,
        sections,
        public_url,
        reach,
        host,
        tables,
        &|_| datagram_binds(doors, sections),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn compose_served_checked(
    gov: Option<Arc<busbar_kernel::governance::GovState>>,
    doors: &[(String, DoorPlane)],
    dispatcher: &Arc<Dispatcher>,
    late: &LateServices,
    sections: &BTreeMap<&'static str, serde_yaml::Value>,
    public_url: Option<&str>,
    reach: &crate::root::door_steps::DoorReach<'_>,
    host: Option<busbar_kernel::plane_driver::GenerationHost>,
    tables: &ServeTables,
    check: &dyn Fn(&Served) -> Result<Vec<crate::root::loader::boot::InboundBind>, String>,
) -> Result<Served, String> {
    let Some(gov) = gov else {
        if !doors.is_empty() {
            tracing::warn!("door planes stay unopened: no governance book to settle on");
        }
        let served = Served::default();
        check(&served)?;
        return Ok(served);
    };
    let post = Arc::new(crate::root::plane_node::NodeEndPost::new(
        crate::root::plane_node::node(),
    ));
    let stage = host.map(|host| HookStage {
        host,
        gov: Arc::clone(&gov),
        journal: Some(Arc::clone(&post) as Arc<dyn busbar_kernel::plane_driver::HookJournal>),
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
        tables,
    )?;
    served.post = Some(post);
    let binds = check(&served)?;

    if !binds.is_empty() {
        served.claim_doors = serve_datagram::ClaimDoors::bind(&binds, |t| {
            crate::root::connector::the().framer_for(t)
        })?;
    }
    Ok(served)
}

pub fn datagram_binds(
    doors: &[(String, DoorPlane)],
    sections: &BTreeMap<&'static str, serde_yaml::Value>,
) -> Result<Vec<crate::root::loader::boot::InboundBind>, String> {
    let mut binds = Vec::new();
    for (instance, plugin) in doors {
        binds.extend(need_binds(instance, &plugin.served(), sections)?);
    }
    Ok(binds)
}

pub(crate) fn need_binds(
    instance: &str,
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    sections: &BTreeMap<&'static str, serde_yaml::Value>,
) -> Result<Vec<crate::root::loader::boot::InboundBind>, String> {
    use busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND;
    let mut binds = Vec::new();
    let Some(section) = sections.get(facts.section) else {
        return Ok(binds);
    };
    for (i, ((direction, _), target)) in
        facts.need_auths.iter().zip(&facts.need_targets).enumerate()
    {
        if *direction != DIRECTION_INBOUND || target.is_empty() {
            continue;
        }
        let at = format!("{}.{target}", facts.section);
        let Some(listen) = target
            .split('.')
            .try_fold(section, |v, k| v.get(k))
            .and_then(|block| block.get("listen"))
            .and_then(serde_yaml::Value::as_str)
        else {
            continue;
        };
        let listen: std::net::SocketAddr = listen
            .parse()
            .map_err(|_| format!("{at}.listen: `{listen}` is not an ip:port address"))?;
        binds.push(crate::root::loader::boot::InboundBind {
            owner: crate::root::loader::boot::BindOwner::Need {
                instance: instance.to_string(),
                kind: KindCode::Plane,
                need: u32::try_from(i).unwrap_or(u32::MAX),
            },
            transport: facts
                .need_transports
                .get(i)
                .map_or_else(String::new, |t| (*t).to_string()),
            at,
            listen,
            tls: None,
            max_conns: crate::root::loader::boot::DEFAULT_MAX_CONNS,
        });
    }
    Ok(binds)
}

pub struct HookStage {
    pub host: busbar_kernel::plane_driver::GenerationHost,

    pub gov: Arc<busbar_kernel::governance::GovState>,

    pub journal: Option<Arc<dyn busbar_kernel::plane_driver::HookJournal>>,
}

struct GovCaller {
    host: Arc<dyn busbar_kernel::plane_driver::EngineHost>,
    gov: Arc<busbar_kernel::governance::GovState>,
}

impl GovCaller {
    fn key(&self, principal: &str) -> Option<Arc<busbar_contract::records::VirtualKey>> {
        self.gov.lookup_by_sub(principal)
    }
}

impl busbar_kernel::plane_driver::CallerFacts for GovCaller {
    fn key(&self, principal: &str) -> Option<busbar_kernel::plane_driver::CallerKey> {
        self.key(principal)
            .map(|k| busbar_kernel::plane_driver::CallerKey {
                id: k.id.clone(),
                name: k.name.clone(),
            })
    }

    fn in_groups(&self, principal: Option<&str>, groups: &[String]) -> bool {
        let group = principal
            .and_then(|p| self.key(p))
            .and_then(|k| k.group.clone());
        self.host.caller_in_hook_groups(group.as_deref(), groups)
    }

    fn rate_headroom(&self, principal: &str, pool: &str) -> Option<f64> {
        let key = self.key(principal)?;
        let pin = self.host.meter_pin()?;
        self.host
            .rate_headroom(&pin, &key, Some(pool), busbar_kernel::store::now())
    }

    fn budget(&self, principal: &str) -> Vec<busbar_contract::hooks::BudgetBucketState> {
        match (self.key(principal), self.host.meter_pin()) {
            (Some(key), Some(pin)) => {
                self.host
                    .budget_state(&pin, &key, busbar_kernel::store::now())
            }
            _ => Vec::new(),
        }
    }

    fn hook_read(&self, hook: &str, principal: Option<&str>, dialect: &str, identity: bool) {
        self.host.hook_read(hook, principal, dialect, identity);
    }
}

struct LiveHooks {
    host: busbar_kernel::plane_driver::GenerationHost,
    gov: Arc<busbar_kernel::governance::GovState>,
    dialects: Vec<String>,

    plane_key: String,
}

impl LiveHooks {
    fn current(&self) -> busbar_kernel::plane_driver::HostHooks {
        let host = (self.host)();
        busbar_kernel::plane_driver::HostHooks {
            host: Arc::clone(&host),
            caller: Arc::new(GovCaller {
                host,
                gov: Arc::clone(&self.gov),
            }),
            dialects: self.dialects.clone(),
            plane_key: self.plane_key.clone(),
        }
    }
}

impl busbar_kernel::plane_driver::HookBinder for LiveHooks {
    fn bind(
        &self,
        bind: &busbar_kernel::plane_driver::Bind<'_>,
    ) -> Option<busbar_kernel::plane_driver::UnitHooks> {
        self.current().bind(bind)
    }

    fn denied(&self, dialect: u32, status: u16) {
        self.current().denied(dialect, status);
    }

    fn dialect(&self, dialect: u32) -> String {
        self.dialects
            .get(dialect as usize)
            .cloned()
            .unwrap_or_default()
    }
}

impl HookStage {
    #[cfg(test)]
    pub(crate) fn new(
        host: busbar_kernel::plane_driver::GenerationHost,
        gov: Arc<busbar_kernel::governance::GovState>,
    ) -> Self {
        Self {
            host,
            gov,
            journal: None,
        }
    }

    fn routed(
        &self,
        plane_key: &str,
        dialects: &[&str],
    ) -> Arc<dyn busbar_kernel::plane_driver::HookBinder> {
        Arc::new(LiveHooks {
            host: Arc::clone(&self.host),
            gov: Arc::clone(&self.gov),
            dialects: dialects.iter().map(|d| (*d).to_string()).collect(),
            plane_key: plane_key.to_string(),
        })
    }

    fn gated(
        &self,
        plane_key: &str,
        dialects: &[&str],
    ) -> Arc<dyn busbar_kernel::plane_driver::HookBinder> {
        let gov = Arc::clone(&self.gov);
        Arc::new(busbar_kernel::plane_driver::HostGatedHooks {
            host: Arc::clone(&self.host),
            plane_key: plane_key.to_string(),
            keys: Arc::new(move |principal: &str| gov.lookup_by_sub(principal)),
            dialects: dialects.iter().map(|d| (*d).to_string()).collect(),
        })
    }
}

#[must_use]
pub fn with_pools(
    mut sections: BTreeMap<&'static str, serde_yaml::Value>,
    pools: &[(
        &'static str,
        BTreeMap<String, busbar_kernel::config::pools::CandidatePoolCfg>,
    )],
) -> BTreeMap<&'static str, serde_yaml::Value> {
    for (key, stated) in pools {
        if let Some(section) = sections.get_mut(key) {
            pools_into(section, stated);
        }
    }
    sections
}

pub type DoorPoolsByKey = Vec<(
    &'static str,
    BTreeMap<String, busbar_kernel::config::pools::CandidatePoolCfg>,
)>;

#[must_use]
pub fn door_pools(
    plane_pools: &BTreeMap<
        &'static str,
        BTreeMap<String, busbar_kernel::config::pools::CandidatePoolCfg>,
    >,
) -> DoorPoolsByKey {
    plane_pools
        .iter()
        .map(|(section, pools)| (*section, pools.clone()))
        .collect()
}

#[must_use]
pub fn installed_door_pools(app: &busbar_kernel::state::App) -> DoorPoolsByKey {
    busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .filter_map(|decl| {
            app.plane_pools(decl.key)
                .map(|pools| (decl.config_section, pools.clone()))
        })
        .collect()
}

fn section_with_pools(
    key: &str,
    written: &serde_yaml::Value,
    pools: &[(
        &'static str,
        BTreeMap<String, busbar_kernel::config::pools::CandidatePoolCfg>,
    )],
) -> serde_yaml::Value {
    let mut section = written.clone();
    for (owner, stated) in pools {
        if *owner == key {
            pools_into(&mut section, stated);
        }
    }
    section
}

fn handed_settings(path: &[&str], section: &serde_yaml::Value) -> Result<Vec<u8>, String> {
    let mut section = plane_settings(section);
    if let Some(map) = section.as_mapping_mut() {
        map.remove(busbar_contract::section::RESERVED_WORK_KEY);
    }
    busbar_kernel::config::filled::plane_bound_bytes(path, &section)
        .map_err(|e| format!("its section: {e}"))
}

fn settings_path(
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
) -> &[&'static str] {
    if handed_keyed(facts) {
        &[]
    } else {
        std::slice::from_ref(&facts.section)
    }
}

pub fn pools_into(
    section: &mut serde_yaml::Value,
    stated: &BTreeMap<String, busbar_kernel::config::pools::CandidatePoolCfg>,
) {
    use busbar_contract::section::{
        POOL_MEMBERS_KEY, POOL_MEMBER_GRANTED_KEY, POOL_MEMBER_NAME_KEY, POOL_MEMBER_TIER_KEY,
        POOL_REPEATABLE_KEY, RESERVED_POOLS_KEY,
    };
    if stated.is_empty() {
        return;
    }
    let serde_yaml::Value::Mapping(section) = section else {
        return;
    };
    let mut map = serde_yaml::Mapping::new();
    for (name, pool) in stated {
        let mut entry = serde_yaml::Mapping::new();
        entry.insert(
            POOL_MEMBERS_KEY.into(),
            serde_yaml::Value::Sequence(
                pool.members
                    .iter()
                    .zip(0u64..)
                    .map(|(m, tier)| {
                        let mut member = serde_yaml::Mapping::new();
                        member.insert(POOL_MEMBER_NAME_KEY.into(), m.as_str().into());
                        member.insert(POOL_MEMBER_TIER_KEY.into(), tier.into());
                        serde_yaml::Value::Mapping(member)
                    })
                    .collect(),
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

        if let Some(block) = pool
            .breaker
            .as_ref()
            .and_then(|b| serde_yaml::to_value(b).ok())
        {
            entry.insert(crate::root::door_steps::POOL_BREAKER_KEY.into(), block);
        }
        map.insert(name.as_str().into(), serde_yaml::Value::Mapping(entry));
    }
    section.insert(RESERVED_POOLS_KEY.into(), serde_yaml::Value::Mapping(map));
}

#[must_use]
pub fn plane_settings(section: &serde_yaml::Value) -> serde_yaml::Value {
    use busbar_contract::section::{POOL_MEMBERS_KEY, POOL_MEMBER_NAME_KEY, RESERVED_POOLS_KEY};
    let mut section = section.clone();
    let pools = section
        .as_mapping_mut()
        .and_then(|m| m.get_mut(RESERVED_POOLS_KEY))
        .and_then(serde_yaml::Value::as_mapping_mut);
    for (_, pool) in pools.into_iter().flat_map(|p| p.iter_mut()) {
        if let Some(pool) = pool.as_mapping_mut() {
            pool.remove(crate::root::door_steps::POOL_BREAKER_KEY);
        }
        let members = pool
            .as_mapping_mut()
            .and_then(|p| p.get_mut(POOL_MEMBERS_KEY))
            .and_then(serde_yaml::Value::as_sequence_mut);
        for member in members.into_iter().flat_map(|m| m.iter_mut()) {
            if let Some(name) = member
                .get(POOL_MEMBER_NAME_KEY)
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_owned)
            {
                *member = serde_yaml::Value::String(name);
            }
        }
    }
    section
}

pub struct DoorEgress<'a> {
    pub reach: &'a crate::root::door_steps::DoorReach<'a>,

    pub journal: Arc<dyn busbar_kernel_egress::ports::Journal>,
}

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
    tables: &ServeTables,
) -> Result<Served, String> {
    let scope = busbar_contract::config_time::ConfigScope::config_time();

    let clock: Arc<dyn busbar_kernel_egress::ports::Clock> =
        Arc::new(crate::root::egress_ports::NodeClock::new());
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
        &clock,
        &scope,
        tables,
    )
}

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
    clock: &Arc<dyn busbar_kernel_egress::ports::Clock>,
    scope: &busbar_contract::config_time::ConfigScope,
    tables: &ServeTables,
) -> Result<Served, String> {
    let mut served = Served {
        tables: tables.clone(),
        ..Served::default()
    };
    if doors.is_empty() {
        return Ok(served);
    }
    let kernel = late
        .kernel()
        .ok_or("the kernel's host services are not composed")?;
    for (instance, plugin) in doors {
        let served_facts = plugin.served();

        let empty = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let section = match sections.get(served_facts.section) {
            Some(section) => section,
            None if served_facts.owns.iter().any(|n| sections.contains_key(n)) => &empty,
            None => {
                tracing::debug!(
                    instance,
                    section = served_facts.section,
                    "door plane not configured"
                );
                continue;
            }
        };

        let settings = settings_of(&served_facts, section, sections);
        let walked = walked_section(&served_facts, section, sections);

        let owned = owned_sections(&served_facts, sections);

        let dialects = egress
            .map(|e| crate::root::door_steps::dialect_facts(&walked, e.reach.providers))
            .unwrap_or_default();
        crate::root::door_steps::member_tls_refusal(&served_facts, &walked)
            .map_err(|e| format!("{instance}: {e}"))?;
        let opened = open(
            plugin,
            settings_path(&served_facts),
            &settings,
            public_url,
            &owned,
            &dialects,
        );

        crate::root::door_steps::owned_anchors_refusal(&served_facts.need_trust, sections)
            .map_err(|e| format!("{instance}: {e}"))?;
        let snapshot = opened.map_err(|e| format!("{instance}: {e}"))?;
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

        let driver = match hooks {
            Some(stage)
                if served_facts.tail_flags & busbar_contract::abi::plane::TAIL_HOOKS_GATED != 0 =>
            {
                driver.with_hooks(stage.gated(plugin.name(), &served_facts.dialects))
            }

            Some(stage) => driver.with_hooks(stage.routed(plugin.name(), &served_facts.dialects)),
            None => driver,
        };

        let driver = match hooks.and_then(|stage| stage.journal.as_ref()) {
            Some(journal) => driver.with_hook_journal(Arc::clone(journal)),
            None => driver,
        };

        let driver =
            if served_facts.tail_flags & busbar_contract::abi::plane::TAIL_REFUSED_PIECE != 0 {
                driver.with_refused_piece()
            } else {
                driver
            };
        let routes = snapshot
            .admin_routes
            .iter()
            .map(|r| ServeRoute {
                verb: r.verb.clone(),
                target: r.target.clone(),
                flags: r.flags,
                audit_verb: r.audit_verb.clone(),
            })
            .collect();

        served
            .tables
            .publish(
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
            clock,
            1,
            bench,
            scope,
            kernel.units(),
        )?;
        let driver = Arc::new(driver);
        kernel.register_plane_cleanup(Arc::downgrade(&driver));
        let probe_schedule = Arc::new(busbar_kernel::probe::ProbeSchedule::new(
            egress
                .and_then(|e| e.reach.models)
                .map_or(0, |m| m.probe_members().0),
        ));
        arm_probes(&driver, &served_facts, &mut live, egress, &probe_schedule);
        let facts = live.facts.clone();
        let reach = egress.map(|e| ApplyReach {
            providers: e.reach.providers.clone(),
            auths: Arc::clone(&e.reach.auths),
            conns: Arc::clone(&e.reach.conns),
            journal: Arc::clone(&e.journal),
            stream_ceiling_secs: e.reach.stream_ceiling_secs,
            catalog: e.reach.catalog.cloned(),
            upgrades: e.reach.upgrades.clone(),
        });
        let live = Arc::new(DoorApply {
            plugin: plugin.clone(),
            served_facts: served_facts.clone(),
            facts: facts.clone(),
            reach,
            live: std::sync::RwLock::new(Arc::new(live)),
            driver: Arc::clone(&driver),
            probe_schedule,
            scope_kinds: declared.scope_kinds.clone(),
            clock: Arc::clone(clock),
            units: Arc::clone(kernel.units()),
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

const SESSION_KEY: &str = "session";
const MODEL_KEY: &str = "model";

#[must_use]
pub fn catalog_routes(
    section: &serde_yaml::Value,
    catalog: &std::collections::HashMap<String, busbar_contract::config::ModelCfg>,
) -> serde_yaml::Value {
    fold_catalog_routes(section, catalog).0
}

fn fold_catalog_routes(
    section: &serde_yaml::Value,
    catalog: &std::collections::HashMap<String, busbar_contract::config::ModelCfg>,
) -> (serde_yaml::Value, Option<String>) {
    use serde_yaml::{Mapping, Value};
    let mut routes = section.clone();
    let named = section
        .get(SESSION_KEY)
        .and_then(|s| s.get(MODEL_KEY))
        .and_then(Value::as_str);
    let (Some(map), Some(model)) = (routes.as_mapping_mut(), named) else {
        return (routes, None);
    };
    let models_key = Value::from(busbar_contract::section::RESERVED_MODELS_KEY);
    let Some(entry) = catalog
        .get(model)
        .filter(|_| !map.contains_key(&models_key))
    else {
        return (routes, None);
    };
    let mut folded = Mapping::new();
    folded.insert("provider".into(), entry.provider.clone().into());
    if let Some(upstream) = &entry.upstream_model {
        folded.insert("upstream_model".into(), upstream.clone().into());
    }
    if let Some(ms) = entry.attempt_timeout_ms {
        folded.insert("attempt_timeout_ms".into(), ms.into());
    }
    let mut models = Mapping::new();
    models.insert(model.into(), Value::Mapping(folded));
    map.insert(models_key, Value::Mapping(models));
    (routes, Some(model.to_string()))
}

fn routes_of(
    section: &serde_yaml::Value,
    catalog: Option<&std::collections::HashMap<String, busbar_contract::config::ModelCfg>>,
) -> (serde_yaml::Value, Option<String>) {
    catalog.map_or_else(
        || (section.clone(), None),
        |c| fold_catalog_routes(section, c),
    )
}

/// A route synthesized from the catalog and a matching declared secondary kind are host facts.
/// Neither an ARRIVE candidate nor a trust counterparty can create this obligation.
fn seal_secondary_scopes(
    facts: &mut DoorFacts,
    scope_kinds: &[&str],
    pools: &DoorPools,
    catalog_entry: Option<&str>,
) {
    facts.secondary_scopes.clear();
    let Some(entry) = catalog_entry.filter(|entry| pools.entries().iter().any(|e| e == entry))
    else {
        return;
    };
    let catalog_scope = busbar_kernel::plane_driver::registry::plane_decl_for_config_section(
        busbar_contract::section::RESERVED_POOLS_KEY,
    )
    .and_then(|decl| decl.scope_kinds.first().copied());
    let Some(kind) = catalog_scope.filter(|kind| scope_kinds.iter().skip(1).any(|k| k == kind))
    else {
        return;
    };
    facts
        .secondary_scopes
        .insert(entry.to_string(), kind.to_string());
}

#[allow(clippy::too_many_arguments)]
fn seal_live(
    instance: &str,
    plugin: &DoorPlane,
    served_facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    scope_kinds: &[&str],
    section: &serde_yaml::Value,
    egress: Option<&DoorEgress<'_>>,
    clock: &Arc<dyn busbar_kernel_egress::ports::Clock>,
    generation: u64,
    bench_below_trip_threshold: Option<bool>,
    scope: &busbar_contract::config_time::ConfigScope,
    units: &Arc<busbar_kernel::host_units::UnitRecords>,
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
    facts.route_cost = served_facts.route_cost.clone();

    facts.stream_ceiling_secs = served_facts.stream_ceiling_secs;

    facts.dialects = served_facts
        .dialects
        .iter()
        .map(|d| (*d).to_string())
        .collect();

    facts.metric_lanes = served_facts
        .metric_lanes
        .iter()
        .map(|w| (*w).to_string())
        .collect();
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

    let binding = plugin.connection_binding();
    let (table, catalog_entry) = routes_of(section, egress.and_then(|e| e.reach.catalog));
    let pools =
        DoorPools::of(&table, served_facts.section).map_err(|e| format!("{instance}: {e}"))?;
    seal_secondary_scopes(&mut facts, scope_kinds, &pools, catalog_entry.as_deref());
    let egress = match egress {
        Some(egress) => {
            let routes = crate::root::door_steps::member_routes(
                &table,
                &pools,
                served_facts,
                egress.reach,
                scope,
            )
            .map_err(|e| format!("{instance}: {e}"))?;
            let sealed = match egress.reach.models {
                Some(models) if models_plane => crate::root::model_egress::compose(
                    &facts,
                    models,
                    binding.owner(),
                    bound_conns(binding.clone(), Arc::clone(&egress.reach.conns)),
                    &routes,
                    Arc::clone(&egress.journal),
                    Arc::clone(clock),
                    egress.reach.stream_ceiling_secs,
                )
                .map(|(e, shown)| (e, Some(shown))),
                _ => crate::root::door_steps::compose_egress(
                    &facts,
                    &pools,
                    binding.owner(),
                    bound_conns(binding.clone(), Arc::clone(&egress.reach.conns)),
                    &routes,
                    Arc::clone(&egress.journal),
                    Arc::clone(clock),
                    egress.reach.stream_ceiling_secs,
                )
                .map(|e| (e, None)),
            };
            let (sealed, shown) = sealed.map_err(|e| format!("{instance}: {e}"))?;

            bind_fetches(plugin, binding.owner(), served_facts, &routes, units);
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

fn bind_fetches(
    plugin: &DoorPlane,
    owner: busbar_contract::conn::InstanceId,
    served_facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    routes: &BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>,
    units: &Arc<busbar_kernel::host_units::UnitRecords>,
) {
    if let Some(conn_table) = plugin.conn_table() {
        crate::root::door_steps::bind_member_fetches(
            served_facts,
            routes,
            owner,
            &*conn_table,
            units,
        );
    }
}

fn arm_probes(
    driver: &Arc<PlaneDriver>,
    served_facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    live: &mut DoorLive,
    egress: Option<&DoorEgress<'_>>,
    schedule: &Arc<busbar_kernel::probe::ProbeSchedule>,
) {
    let (Some(sealed), Some(models)) = (&live.egress, egress.and_then(|e| e.reach.models)) else {
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

fn owned_sections(
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    sections: &BTreeMap<&'static str, serde_yaml::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    facts
        .owns
        .iter()
        .filter_map(|name| {
            let value = serde_json::to_value(sections.get(name)?).ok()?;
            let value = busbar_kernel::config::filled::plane_bound(&[name], value);
            Some(((*name).to_string(), value))
        })
        .collect()
}

fn owned_bytes(owned: &serde_json::Map<String, serde_json::Value>) -> Result<Vec<u8>, String> {
    if owned.is_empty() {
        Ok(Vec::new())
    } else {
        serde_json::to_vec(owned).map_err(|e| format!("its owned sections: {e}"))
    }
}

fn handed_keyed(facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts) -> bool {
    facts.section == busbar_contract::section::RESERVED_POOLS_KEY || !facts.consumed.is_empty()
}

fn settings_of(
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    section: &serde_yaml::Value,
    sections: &BTreeMap<&'static str, serde_yaml::Value>,
) -> serde_yaml::Value {
    if !handed_keyed(facts) {
        return section.clone();
    }
    let own = if facts.section == busbar_contract::section::RESERVED_POOLS_KEY {
        section.clone()
    } else {
        let mut own = plane_settings(section);
        if let Some(map) = own.as_mapping_mut() {
            map.remove(busbar_contract::section::RESERVED_WORK_KEY);
        }
        own
    };
    let mut keyed = serde_yaml::Mapping::new();
    keyed.insert(facts.section.into(), own);
    for name in &facts.consumed {
        if let Some(value) = sections.get(name) {
            keyed.insert((*name).into(), value.clone());
        }
    }
    serde_yaml::Value::Mapping(keyed)
}

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

fn open(
    plugin: &DoorPlane,
    path: &[&str],
    section: &serde_yaml::Value,
    public_url: Option<&str>,
    owned: &serde_json::Map<String, serde_json::Value>,
    dialects: &[busbar_contract::plane_calls::DialectFacts],
) -> Result<OwnedSnapshot, String> {
    let settings = handed_settings(path, section)?;
    let owned = owned_bytes(owned)?;
    let url = public_url.unwrap_or_default();

    let providers = crate::root::loader::dispatch::kinds::plane::provider_facts(dialects);
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
            providers: if providers.is_empty() {
                std::ptr::null()
            } else {
                providers.as_ptr()
            },
            providers_len: providers.len(),
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
        return Err(called.open_failure(plugin.name()));
    }
    snapshot.ok_or_else(|| "its snapshot did not pass the host's checks".to_string())
}

pub struct DataRoutes {
    served: Served,

    claim_doors: Option<Arc<OnceLock<serve_datagram::ClaimDoors>>>,
    post: Arc<crate::root::plane_node::NodeEndPost>,

    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,

    guests: busbar_kernel::guest::GuestList,
    of_line: std::collections::HashMap<(String, u32), DoorClaim>,

    frames: Mutex<std::collections::HashMap<u64, Arc<busbar_kernel::state::App>>>,
}

struct UnitFrame<'r> {
    routes: &'r DataRoutes,
    unit: u64,
}

impl Drop for UnitFrame<'_> {
    fn drop(&mut self) {
        self.routes.frames_lock().remove(&self.unit);
    }
}

const NEST_REPLY_MAX: usize = 16 << 20;

pub const NEST_UNSERVED: &str = "no plane serves the nested unit's claim";

pub const NEST_PARENT_GONE: &str = "the nested unit's parent is not in flight";

pub const NEST_UNREAD: &str = "the nested unit's reply could not be read";

pub struct DoorNests {
    routes: NestRoutes,
    runtime: tokio::runtime::Handle,
    detached: Option<Arc<busbar_kernel::detached::DetachedTasks>>,
}

type NestRoutes = Arc<Mutex<Vec<std::sync::Weak<DataRoutes>>>>;

impl busbar_kernel::host_services::NestRoute for DoorNests {
    fn nest(
        &self,
        nest: busbar_kernel::host_services::Nest,
        done: busbar_kernel::host_services::NestDone,
    ) {
        let routes: Vec<_> = self
            .routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .collect();
        let Some((routes, bound)) = routes
            .into_iter()
            .find_map(|routes| routes.parent_of(&nest).map(|bound| (routes, bound)))
        else {
            done(busbar_kernel::host_services::NestReply::Unserved(
                NEST_PARENT_GONE,
            ));
            return;
        };

        let child = async move { done(routes.nested(nest, bound).await) };
        drop(match &self.detached {
            Some(detached) => detached.spawn_on(&self.runtime, child),
            None => self.runtime.spawn(child),
        });
    }
}

impl std::fmt::Debug for DataRoutes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataRoutes")
            .field("served", &self.served)
            .finish_non_exhaustive()
    }
}

pub fn data_routes(
    served: Served,
    data_chain: &[ChainAuth],
    core: &[(
        String,
        busbar_contract::abi::mechanism::route::RouteMethod,
        busbar_contract::abi::mechanism::route::RouteAuth,
    )],
) -> Result<Vec<busbar_kernel::plane_routes::PlaneRouteSpec>, String> {
    if served.planes.iter().all(|p| p.snapshot.claims.is_empty()) {
        return Ok(Vec::new());
    }
    door_routes(
        served,
        || crate::root::kernel::ROOT_CARD.pin(),
        data_chain,
        core,
    )
}

pub type DataMounts = (
    Vec<busbar_kernel::plane_routes::PlaneRouteSpec>,
    Vec<busbar_kernel::plane_routes::PlaneSessionSpec>,
    Vec<busbar_kernel::plane_routes::PlaneRefusalSpec>,
    Option<busbar_kernel::plane_routes::PlaneRefuseByPathFn>,
);

pub fn data_mounts(
    served: Served,
    data_chain: &[ChainAuth],
    core: &[(
        String,
        busbar_contract::abi::mechanism::route::RouteMethod,
        busbar_contract::abi::mechanism::route::RouteAuth,
    )],
    upgrades: &[&str],
    offers: &[TransportOffer],
) -> Result<DataMounts, String> {
    door_mounts(
        served,
        || crate::root::kernel::ROOT_CARD.pin(),
        data_chain,
        core,
        upgrades,
        offers,
    )
    .and_then(|m| {
        busbar_kernel::plane_routes::pair_door_refusals(&m.routes, &m.sessions, &m.refusals)?;
        Ok((m.routes, m.sessions, m.refusals, m.refuse_by_path))
    })
}

#[allow(clippy::too_many_arguments)]
pub fn data_mounts_with_listeners(
    served: Served,
    app: &busbar_kernel::state::App,
    plan: &ListenerPlan,
    at: &str,
    data_chain: &[ChainAuth],
    core: &[(String, RouteMethod, RouteAuth)],
    upgrades: &[&str],
    offers: &[TransportOffer],
) -> Result<DataMounts, String> {
    let mounts = door_mounts_planned(
        served,
        || crate::root::kernel::ROOT_CARD.pin(),
        data_chain,
        core,
        upgrades,
        offers,
        Some((plan, app, at)),
    )?;
    busbar_kernel::plane_routes::pair_door_refusals(
        &mounts.routes,
        &mounts.sessions,
        &mounts.refusals,
    )?;
    Ok((
        mounts.routes,
        mounts.sessions,
        mounts.refusals,
        mounts.refuse_by_path,
    ))
}

pub struct DoorRequest {
    pub method: axum::http::Method,

    pub uri: axum::http::Uri,

    pub headers: axum::http::HeaderMap,

    pub body: Bytes,

    pub gov: busbar_contract::records::PlaneRequestCtx,

    pub credential: Option<busbar_contract::redacted::Secret<Vec<u8>>>,

    pub ticket: Option<Vec<u8>>,

    pub app: Arc<busbar_kernel::state::App>,

    pub scheme: u8,

    pub consumed_fields: Vec<(String, String)>,
}

fn line_auth(flags: u32, data_chain: &[ChainAuth]) -> busbar_kernel::guest::LineAuth {
    if flags & CLAIM_OPEN != 0 {
        busbar_kernel::guest::LineAuth::None
    } else {
        chain_auth(data_chain)
    }
}

pub type ChainAuth = (String, busbar_contract::abi::auth::AuthPoints);

#[cfg(test)]
#[path = "tests/listener_plan.rs"]
mod listener_plan_tests;

fn listener_method_bits(method: RouteMethod) -> u32 {
    busbar_contract::abi::transport::route::method_bit(method.as_str())
        | if method == RouteMethod::Get {
            busbar_contract::abi::transport::route::METHOD_HEAD
        } else {
            0
        }
}

/// The process's physical listeners and its boot-mounted plane routes. Application candidates
/// supply their own plugin routes, auth instances and limits when each list is sealed.
#[derive(Debug)]
pub struct ListenerPlan {
    initial: crate::root::boot::ListenerNeeds,
    served: std::sync::OnceLock<Served>,
    upgrades: std::sync::OnceLock<Vec<String>>,
    claim_doors: Arc<OnceLock<serve_datagram::ClaimDoors>>,
    planes: std::sync::OnceLock<Vec<ListenerPlaneLine>>,
    plane_sections: std::sync::OnceLock<std::collections::HashMap<String, (&'static str, bool)>>,
    plane_keys: std::sync::OnceLock<std::collections::HashMap<String, String>>,
    offers: Vec<TransportOffer>,
    framers: std::collections::HashMap<String, (u64, bool)>,
    refusals: Mutex<std::collections::HashMap<String, Vec<PlaneRefusalSpec>>>,
    nests: NestRoutes,
    plugin_mounts: std::sync::OnceLock<Vec<(String, RouteMethod, bool)>>,
}

#[derive(Debug)]
struct ListenerPlaneLine {
    line: busbar_kernel::guest::Line,
    transport: String,
    root_only: bool,
}

pub type PreparedListeners =
    std::collections::HashMap<String, Arc<busbar_kernel::router::PreparedListener>>;

impl ListenerPlan {
    pub fn new(
        initial: crate::root::boot::ListenerNeeds,
        offers: Vec<TransportOffer>,
        framer_for: &FramerFor,
    ) -> Self {
        let framers = offers
            .iter()
            .filter_map(|(scheme, _)| {
                let door = framer_for(scheme)?;
                let facts = door.facts();
                if facts.role != busbar_contract::abi::transport::ROLE_FRAMER || !door.accepts() {
                    return None;
                }
                Some((
                    (*scheme).to_string(),
                    (door.instance().filter(|id| *id != 0)?, facts.datagram),
                ))
            })
            .collect();
        Self {
            initial,
            served: std::sync::OnceLock::new(),
            upgrades: std::sync::OnceLock::new(),
            claim_doors: Arc::default(),
            planes: std::sync::OnceLock::new(),
            plane_sections: std::sync::OnceLock::new(),
            plane_keys: std::sync::OnceLock::new(),
            offers,
            framers,
            refusals: Mutex::default(),
            nests: Arc::default(),
            plugin_mounts: std::sync::OnceLock::new(),
        }
    }

    pub fn binds(&self) -> &[crate::root::loader::boot::InboundBind] {
        &self.initial.binds
    }

    pub fn hold_refusals(&self, at: &str, refusals: Vec<PlaneRefusalSpec>) {
        self.refusals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(at.to_string(), refusals);
    }

    pub fn share_claim_doors(&self, served: &mut Served) -> Result<(), String> {
        served.nests = Some(Arc::clone(&self.nests));
        for need in &self.initial.needs {
            if !self
                .framers
                .get(&need.transport)
                .is_some_and(|(_, datagram)| *datagram)
            {
                continue;
            }
            if let Some(bind) = self.initial.binds.iter().find(|bind| bind.at == need.at) {
                if let Some(door) = served.claim_doors.get(&bind.transport) {
                    served.claim_doors.insert(&need.transport, door);
                } else {
                    return Err(format!(
                        "{}: its validated claim door was not bound",
                        need.instance
                    ));
                }
            }
        }
        self.claim_doors
            .set(served.claim_doors.clone())
            .map_err(|_| "physical claim doors were already installed".to_string())
    }

    pub fn guests(
        &self,
        app: &busbar_kernel::state::App,
        at: &str,
    ) -> Result<busbar_kernel::guest::GuestList, String> {
        self.lists(app)?
            .into_iter()
            .find(|(name, _)| name == at)
            .map(|(_, guests)| guests)
            .ok_or_else(|| format!("listener {at} has no guest list"))
    }

    pub fn stream_binds(&self) -> impl Iterator<Item = &crate::root::loader::boot::InboundBind> {
        self.initial.binds.iter().filter(|bind| {
            self.framers
                .get(&bind.transport)
                .is_some_and(|(_, datagram)| !datagram)
        })
    }

    pub fn mount_planes(
        &self,
        served: &Served,
        app: &busbar_kernel::state::App,
        upgrades: &[&str],
    ) -> Result<(), String> {
        use busbar_contract::abi::transport::route::PATH_EXACT;
        use busbar_kernel::guest::{Claimant, Line, LineAuth, Route};
        let cfg = self.config(app)?;
        let chain: Vec<_> = cfg
            .data_chain
            .iter()
            .map(|name| (name.clone(), app.auth.position_points(name)))
            .collect();
        let mut lines = Vec::new();
        for plane in &served.planes {
            for (rung, claim) in plane.snapshot.claims.iter().enumerate() {
                if !routed(claim) || lines::carrier() == Some(claim.carrier.as_str()) {
                    continue;
                }
                let rung = u32::try_from(rung).map_err(|_| "plane claim index does not fit u32")?;
                lines.push(ListenerPlaneLine {
                    line: claim_line(&plane.instance, rung, claim, &chain, upgrades, &self.offers)?
                        .0,
                    transport: claim.carrier.clone(),
                    root_only: false,
                });
            }
            for (rung, route) in plane
                .snapshot
                .admin_routes
                .iter()
                .enumerate()
                .filter(|(_, route)| route.flags & busbar_contract::abi::plane::ROUTE_PUBLIC != 0)
            {
                let method = METHODS
                    .into_iter()
                    .find(|method| method.as_str().eq_ignore_ascii_case(&route.verb))
                    .ok_or_else(|| {
                        format!(
                            "{}: unsupported public route method {}",
                            plane.instance, route.verb
                        )
                    })?;
                lines.push(ListenerPlaneLine {
                    line: Line {
                        route: Route {
                            methods: listener_method_bits(method),
                            path_form: PATH_EXACT,
                            path: route.target.clone(),
                            fields: Vec::new(),
                            rung: u32::try_from(plane.snapshot.claims.len() + rung)
                                .map_err(|_| "plane route index does not fit u32")?,
                        },
                        claimant: Claimant::Plane(plane.instance.clone()),
                        dialect: 0,
                        auth: LineAuth::None,
                        upgrade: None,
                        offered: crate::root::doors::offers_unstated(),
                    },
                    transport: crate::root::listener::framed::DATA_SCHEME.into(),
                    root_only: true,
                });
            }
        }
        self.plane_keys
            .set(
                served
                    .planes
                    .iter()
                    .map(|plane| (plane.instance.clone(), plane.live.plugin.name().to_string()))
                    .collect(),
            )
            .map_err(|_| "plane listener keys were already mounted")?;
        self.plane_sections
            .set(
                served
                    .planes
                    .iter()
                    .map(|plane| {
                        (
                            plane.instance.clone(),
                            (
                                plane.live.served_facts.section,
                                plane.live.served_facts.fallback,
                            ),
                        )
                    })
                    .collect(),
            )
            .map_err(|_| "plane listener sections were already mounted")?;
        self.planes
            .set(lines)
            .map_err(|_| "plane listener routes were already mounted")?;
        self.served
            .set(served.clone())
            .map_err(|_| "plane listener handlers were already mounted")?;
        self.upgrades
            .set(
                upgrades
                    .iter()
                    .map(|scheme| (*scheme).to_string())
                    .collect(),
            )
            .map_err(|_| "plane listener upgrades were already mounted")?;
        self.check(app)?;
        self.freeze_mounts(app)
    }

    fn freeze_mounts(&self, app: &busbar_kernel::state::App) -> Result<(), String> {
        self.plugin_mounts
            .set(
                app.plugin_routes
                    .descriptors()
                    .into_iter()
                    .map(|route| {
                        (
                            route.path.to_string(),
                            route.method,
                            route.auth == RouteAuth::Admin,
                        )
                    })
                    .collect(),
            )
            .map_err(|_| "plugin mounts were already frozen")?;
        Ok(())
    }

    pub fn data_guests(
        &self,
        app: &busbar_kernel::state::App,
    ) -> Result<busbar_kernel::guest::GuestList, String> {
        self.lists(app)?
            .into_iter()
            .find(|(at, _)| at == "listen")
            .map(|(_, guests)| guests)
            .ok_or_else(|| "the root data listener is unavailable".into())
    }

    fn config<'a>(
        &self,
        app: &'a busbar_kernel::state::App,
    ) -> Result<&'a crate::root::door_steps::DoorConfig, String> {
        app.config_projection
            .as_ref()
            .and_then(|c| c.downcast_ref())
            .ok_or_else(|| "listener candidate has no root configuration projection".into())
    }

    fn needs(
        &self,
        app: &busbar_kernel::state::App,
    ) -> Result<crate::root::boot::ListenerNeeds, String> {
        let cfg = self.config(app)?;
        crate::root::boot::candidate_listener_needs(app, &cfg.sections, cfg.root_binds.clone()?)
            .unwrap_or_else(|| cfg.listeners.clone())
    }

    pub fn check(&self, app: &busbar_kernel::state::App) -> Result<(), String> {
        let lists = self.lists(app)?;
        self.check_mounts(app)?;
        for (_, guests) in lists {
            self.auths(app, &guests)?;
        }
        self.prepare(app)?;
        Ok(())
    }

    fn prepare(&self, app: &busbar_kernel::state::App) -> Result<(), String> {
        let Some(served) = self.served.get() else {
            return Ok(());
        };
        let cfg = self.config(app)?;
        if cfg.listener_routes.get().is_some() {
            return Ok(());
        }
        let chain: Vec<_> = cfg
            .data_chain
            .iter()
            .map(|name| (name.clone(), app.auth.position_points(name)))
            .collect();
        let upgrades: Vec<_> = self
            .upgrades
            .get()
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect();
        let mut prepared = PreparedListeners::new();
        for (at, guests) in self.lists(app)? {
            let core = if at == "listen" {
                busbar_kernel::base_data_core_lines(app)
            } else {
                Vec::new()
            };
            let (doors, sessions, refusals, refuse_by_path) = data_mounts_with_listeners(
                served.clone(),
                app,
                self,
                &at,
                &chain,
                &core,
                &upgrades,
                &self.offers,
            )?;
            let plugins = app.plugin_routes.for_listener(&guests);
            let router = busbar_kernel::router::PreparedListener::new(
                app,
                &plugins,
                doors,
                sessions,
                refusals,
                refuse_by_path,
                at == "listen",
            )?
            .with_dispatch_layer(crate::root::listener::deferred_dispatch_layer);
            prepared.insert(at, Arc::new(router));
        }

        let _ = cfg.listener_routes.set(prepared);
        Ok(())
    }

    pub fn prepared(
        &self,
        app: &busbar_kernel::state::App,
        at: &str,
    ) -> Option<Arc<busbar_kernel::router::PreparedListener>> {
        self.config(app)
            .ok()?
            .listener_routes
            .get()?
            .get(at)
            .cloned()
    }

    pub fn mounted_plugin_paths(
        &self,
        app: &busbar_kernel::state::App,
    ) -> Option<std::collections::HashSet<String>> {
        self.config(app).ok()?.listener_routes.get()?;
        let mut paths: std::collections::HashSet<_> = self
            .plugin_mounts
            .get()?
            .iter()
            .filter(|(_, _, admin)| *admin)
            .map(|(path, _, _)| path.clone())
            .collect();
        paths.extend(
            app.plugin_routes
                .descriptors()
                .into_iter()
                .filter(|route| route.auth != RouteAuth::Admin && route.dispatch_available)
                .map(|route| route.path.to_string()),
        );
        Some(paths)
    }

    pub fn router(
        self: &Arc<Self>,
        handle: &Arc<busbar_kernel::state::AppHandle>,
        at: String,
        body_limit: usize,
        max_inbound: usize,
        server_timing: bool,
    ) -> axum::Router {
        let plan = Arc::clone(self);
        busbar_kernel::router::serve_listener_generations(
            Arc::clone(handle),
            move |app| plan.prepared(app, &at),
            body_limit,
            max_inbound,
            server_timing,
        )
    }

    fn check_mounts(&self, app: &busbar_kernel::state::App) -> Result<(), String> {
        for route in app.plugin_routes.descriptors() {
            if !route.dispatch_available
                && self
                    .plugin_mounts
                    .get()
                    .is_none_or(|mounted| mounted.iter().any(|(path, _, _)| path == route.path))
            {
                return Err(format!("{}: the candidate has no opened SERVE dispatcher for this mounted route; restart required", route.path));
            }
        }
        if let Some(mounted) = self.plugin_mounts.get() {
            for route in app.plugin_routes.descriptors() {
                if mounted.iter().any(|(path, _, _)| path == route.path)
                    && !mounted.iter().any(|(path, method, admin)| {
                        path == route.path
                            && *admin == (route.auth == RouteAuth::Admin)
                            && (!*admin || *method == route.method)
                    })
                {
                    return Err(format!("{}: changing a mounted admin plugin method or physical admin placement requires a restart", route.path));
                }
            }
        }
        Ok(())
    }

    fn auths(
        &self,
        app: &busbar_kernel::state::App,
        guests: &busbar_kernel::guest::GuestList,
    ) -> Result<
        std::collections::HashMap<String, Arc<dyn busbar_contract::auth_calls::AuthCalls>>,
        String,
    > {
        let declared = self.needs(app)?;
        let mut auths = std::collections::HashMap::new();
        for name in guests
            .lines()
            .iter()
            .filter_map(|line| match &line.auth {
                busbar_kernel::guest::LineAuth::Chain(names, _) => Some(names),
                busbar_kernel::guest::LineAuth::None => None,
            })
            .flatten()
        {
            if name == busbar_kernel::config::KEYS_MODULE {
                continue;
            }
            let calls = app
                .auth
                .position_calls(name)
                .or_else(|| {
                    declared
                        .needs
                        .iter()
                        .chain(&self.initial.needs)
                        .filter_map(|need| app.inbound_default_auth(&need.auth).ok().flatten())
                        .find(|default| default.provider == *name)
                        .map(|default| default.calls)
                })
                .ok_or_else(|| format!("listener candidate has no opened auth provider {name}"))?;
            auths.insert(name.clone(), calls);
        }
        Ok(auths)
    }

    fn lists(
        &self,
        app: &busbar_kernel::state::App,
    ) -> Result<Vec<(String, busbar_kernel::guest::GuestList)>, String> {
        use crate::root::loader::boot::BindOwner;
        use busbar_contract::abi::mechanism::KindCode;
        use busbar_contract::abi::transport::route::{PATH_EXACT, PATH_PATTERN};
        use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
        let cfg = self.config(app)?;
        let next = self.needs(app)?;
        let physical_bind = |at: &str| {
            let proposed = next.binds.iter().find(|bind| bind.at == at);
            self.initial
                .binds
                .iter()
                .find(|old| {
                    proposed.is_some_and(|bind| {
                        old.listen == bind.listen
                            && old.tls == bind.tls
                            && old.max_conns == bind.max_conns
                            && (old.at == bind.at || bind.listen.port() != 0)
                    })
                })
                .or_else(|| {
                    self.initial
                        .binds
                        .iter()
                        .find(|old| old.at == at && proposed.is_none())
                })
        };
        for bind in &next.binds {
            if physical_bind(&bind.at).is_none() {
                return Err(format!(
                    "{}: changing or adding a physical listener requires a restart",
                    bind.at
                ));
            }
        }
        let mut datagram_claims = std::collections::HashMap::new();
        for need in &next.needs {
            if need.kind == KindCode::Plane && self.planes.get().is_some_and(|lines|
                !lines.iter().any(|route| matches!(&route.line.claimant, Claimant::Plane(owner) if owner == &need.instance)
                    && !route.root_only && route.transport == need.transport)) {
                return Err(format!("{}: inbound need {} has no served plane claim", need.instance, need.need));
            }
            let Some((owner, datagram)) = self.framers.get(&need.transport) else {
                return Err(format!(
                    "{}: inbound need {} has no accepting framer for {}",
                    need.instance, need.need, need.transport
                ));
            };
            if *datagram {
                if need.kind != KindCode::Plane || need.at == "listen" {
                    return Err(format!(
                        "{}: datagram need {} has no physical plane claim door",
                        need.instance, need.need
                    ));
                }
                let bind = physical_bind(&need.at)
                    .ok_or_else(|| format!("{}: unknown datagram listener", need.at))?;
                if let Some(previous) = datagram_claims.insert(&need.transport, &bind.at) {
                    if previous != &bind.at {
                        return Err(format!(
                            "{}: a second claim door for {}",
                            need.at, need.transport
                        ));
                    }
                }
            }
            {
                let bind = physical_bind(&need.at)
                    .ok_or_else(|| format!("{}: unknown physical listener", need.at))?;
                let scheme = if bind.owner == BindOwner::Root {
                    crate::root::listener::framed::DATA_SCHEME
                } else {
                    &bind.transport
                };
                let physical = self.framers.get(scheme);
                // App construction checks physical framing before OPEN has mounted plane
                // claims. Defer only that claim proof; mount_planes checks again with both
                // snapshots installed, before any listener is published.
                let upgrade_claims_match = match (self.planes.get(), self.upgrades.get()) {
                    (None, None) => true,
                    (Some(lines), Some(upgrades)) => upgrades.contains(&need.transport)
                        && lines.iter().any(|route| {
                            matches!(&route.line.claimant, Claimant::Plane(instance) if instance == &need.instance)
                                && !route.root_only
                                && route.transport == need.transport
                                && route.line.upgrade.as_deref() == Some(need.transport.as_str())
                        }),
                    _ => false,
                };
                let upgrades_here = bind.owner == BindOwner::Root
                    && bind.at == "listen"
                    && need.kind == KindCode::Plane
                    && !*datagram
                    && physical.is_some_and(|(_, datagram)| !datagram)
                    && self
                        .framers
                        .get(crate::root::listener::framed::upgrade_claim(
                            bind.tls.is_some(),
                        ))
                        .is_some_and(|(upgrade_owner, datagram)| {
                            upgrade_owner == owner && !datagram
                        })
                    && upgrade_claims_match;
                if bind.at == "admin_listen"
                    || (physical.is_none_or(|(physical, _)| physical != owner) && !upgrades_here)
                {
                    return Err(format!(
                        "{}: inbound need {} has incompatible physical framing at {}",
                        need.instance, need.need, bind.at
                    ));
                }
            }
            if matches!(need.kind, KindCode::Hook | KindCode::Export)
                && !app.plugin_routes.descriptors().iter().any(|route| {
                    route.source_instance == need.instance
                        && route.dispatch_available
                        && (!route.persistent || self.initial.needs.contains(need))
                        && route.auth != RouteAuth::Admin
                        && match need.kind {
                            KindCode::Hook => {
                                route.kind == busbar_kernel::plugin_routes::RouteKind::Hook
                            }
                            _ => route.kind == busbar_kernel::plugin_routes::RouteKind::Export,
                        }
                })
            {
                return Err(format!(
                    "{}: inbound need {} has no data SERVE route",
                    need.instance, need.need
                ));
            }
        }
        let chain: Vec<_> = cfg
            .data_chain
            .iter()
            .map(|name| (name.clone(), app.auth.position_points(name)))
            .collect();
        let data_mode = DataChainMode::for_candidate(app, &chain);
        let default_auth = |mut line: Line,
                            need: &crate::root::boot::ListenerNeed,
                            allow_operator_open: bool|
         -> Result<Line, String> {
            if cfg.data_chain.is_empty() && matches!(line.auth, LineAuth::Chain(..)) {
                if let Some(default) = app.inbound_default_auth(&need.auth)? {
                    line.auth = chain_auth(&[(default.provider, default.points)]);
                } else if allow_operator_open {
                    line.auth = inherited_data_auth(&chain, data_mode);
                }
            }
            Ok(line)
        };
        let mut partitions: Vec<(String, Vec<Line>)> = self
            .initial
            .binds
            .iter()
            .filter(|bind| {
                bind.at != "admin_listen"
                    && !self
                        .framers
                        .get(&bind.transport)
                        .is_some_and(|(_, datagram)| *datagram)
            })
            .map(|bind| (bind.at.clone(), Vec::new()))
            .collect();
        let place = |partitions: &mut Vec<(String, Vec<Line>)>,
                     at: &str,
                     mut line: Line|
         -> Result<(), String> {
            let bind =
                physical_bind(at).ok_or_else(|| format!("listener {at} was not bound at boot"))?;
            let scheme = if bind.owner == BindOwner::Root {
                crate::root::listener::framed::DATA_SCHEME
            } else {
                &bind.transport
            };
            line.offered = offered_by(&self.offers, scheme);
            if matches!(line.auth, LineAuth::Chain(..)) && !cfg.data_chain.is_empty() {
                line.auth = chain_auth(&chain);
            }
            let lines = &mut partitions
                .iter_mut()
                .find(|(name, _)| name == &bind.at)
                .ok_or_else(|| {
                    format!("{at}: a data route cannot be placed on the admin listener")
                })?
                .1;
            let already_served = lines.iter().any(|old| {
                let mut equivalent = line.clone();
                if matches!((&old.claimant, &line.claimant), (Claimant::Need(a, _), Claimant::Need(b, _)) if a == b) {
                    equivalent.claimant = old.claimant.clone();
                }
                *old == equivalent
            });
            if !already_served {
                lines.push(line);
            }
            Ok(())
        };
        let assigned = |kind: KindCode, owner: &str, transport: Option<&str>| {
            next.needs
                .iter()
                .filter(move |need| {
                    need.kind == kind
                        && need.instance == owner
                        && transport.is_none_or(|scheme| need.transport == scheme)
                })
                .collect::<Vec<_>>()
        };
        for route in self.planes.get().into_iter().flatten() {
            let mut line = route.line.clone();
            if matches!(line.auth, LineAuth::Chain(..)) {
                line.auth = chain_auth(&chain);
            }
            let transport = &route.transport;
            let Claimant::Plane(owner) = &line.claimant else {
                continue;
            };
            let allow_operator_open = self
                .served
                .get()
                .and_then(|served| served.planes.iter().find(|plane| plane.instance == *owner))
                .and_then(|plane| {
                    plane
                        .snapshot
                        .claims
                        .get(line.route.rung as usize)
                        .map(|claim| {
                            operator_open_claim(
                                data_mode,
                                plane.live.served_facts.section,
                                claim.flags,
                            )
                        })
                })
                .unwrap_or(false);
            if self
                .plane_sections
                .get()
                .and_then(|sections| sections.get(owner))
                .is_some_and(|(section, fallback)| {
                    !fallback
                        && app
                            .plane_sections
                            .as_ref()
                            .is_some_and(|sections| !sections.contains(section))
                })
            {
                continue;
            }
            if route.root_only {
                place(&mut partitions, "listen", line.clone())?;
                continue;
            }
            let mut needs = assigned(KindCode::Plane, owner, Some(transport));
            if needs.is_empty() && line.upgrade.is_some() {
                needs = assigned(KindCode::Plane, owner, None)
                    .into_iter()
                    .filter(|need| {
                        self.framers
                            .get(&need.transport)
                            .is_some_and(|(_, datagram)| !datagram)
                    })
                    .collect();
            }
            if needs.is_empty() {
                if next
                    .needs
                    .iter()
                    .any(|need| need.kind == KindCode::Plane && need.instance == *owner)
                    && line.upgrade.is_none()
                {
                    return Err(format!(
                        "{owner}: claim {} has no inbound need for its transport {transport}",
                        line.route.path
                    ));
                }
                if allow_operator_open && matches!(line.auth, LineAuth::Chain(..)) {
                    line.auth = inherited_data_auth(&chain, data_mode);
                }
                place(&mut partitions, "listen", line.clone())?;
            } else {
                for need in needs {
                    if self
                        .framers
                        .get(&need.transport)
                        .is_some_and(|(_, datagram)| *datagram)
                    {
                        place(
                            &mut partitions,
                            "listen",
                            default_auth(line.clone(), need, allow_operator_open)?,
                        )?;
                    } else {
                        place(
                            &mut partitions,
                            &need.at,
                            default_auth(line.clone(), need, allow_operator_open)?,
                        )?;
                    }
                }
            }
        }
        for (rung, (path, method, auth)) in (0u32..).zip(busbar_kernel::base_data_core_lines(app)) {
            place(
                &mut partitions,
                "listen",
                Line {
                    route: Route {
                        methods: listener_method_bits(method),
                        path_form: if path.contains('{') {
                            PATH_PATTERN
                        } else {
                            PATH_EXACT
                        },
                        path,
                        fields: Vec::new(),
                        rung,
                    },
                    claimant: Claimant::Clean(CORE_CLAIMANT.into()),
                    dialect: 0,
                    auth: match auth {
                        RouteAuth::None => LineAuth::None,
                        RouteAuth::Key => inherited_data_auth(&chain, data_mode),
                        RouteAuth::Admin => chain_auth(&chain),
                    },
                    upgrade: None,
                    offered: crate::root::doors::offers_unstated(),
                },
            )?;
        }
        for (rung, route) in (0u32..).zip(app.plugin_routes.descriptors()) {
            if route.auth == RouteAuth::Admin || !route.dispatch_available {
                continue;
            }
            let kind = match route.kind {
                busbar_kernel::plugin_routes::RouteKind::Hook => KindCode::Hook,
                busbar_kernel::plugin_routes::RouteKind::Export => KindCode::Export,
            };
            let needs = if route.persistent {
                self.initial
                    .needs
                    .iter()
                    .filter(|need| need.kind == kind && need.instance == route.source_instance)
                    .collect()
            } else {
                assigned(kind, route.source_instance, None)
            };
            let line = |need| Line {
                route: Route {
                    methods: listener_method_bits(route.method),
                    path_form: PATH_EXACT,
                    path: route.path.into(),
                    fields: Vec::new(),
                    rung,
                },
                claimant: Claimant::Need(route.source_instance.into(), need),
                dialect: 0,
                auth: if route.auth == RouteAuth::None {
                    LineAuth::None
                } else {
                    chain_auth(&chain)
                },
                upgrade: None,
                offered: crate::root::doors::offers_unstated(),
            };
            if needs.is_empty() {
                let mut line = line(0);
                if matches!(line.auth, LineAuth::Chain(..)) {
                    line.auth = inherited_data_auth(&chain, data_mode);
                }
                place(&mut partitions, "listen", line)?;
            } else {
                for need in needs {
                    place(
                        &mut partitions,
                        &need.at,
                        default_auth(line(need.need), need, true)?,
                    )?;
                }
            }
        }
        partitions
            .into_iter()
            .map(|(at, lines)| {
                GuestList::seal(lines)
                    .map(|list| (at.clone(), list))
                    .map_err(|refusal| guest_refusal(&at, refusal))
            })
            .collect()
    }

    pub fn policy(self: &Arc<Self>, at: String) -> crate::root::inbound::ListenerPolicy {
        let plan = Arc::clone(self);
        Arc::new(move |source| {
            let guests = plan
                .lists(&source.app)?
                .into_iter()
                .find(|(name, _)| *name == at)
                .map(|(_, guests)| guests)
                .ok_or_else(|| format!("listener {at} is unavailable"))?;
            let auths = plan.auths(&source.app, &guests)?;
            let owned_guests = guests.clone();
            let keys = plan.plane_keys.get().cloned().unwrap_or_default();
            let legacy_fallback = at == "listen";
            let scope = busbar_kernel::inbound::ListenerScope {
                legacy_fallback,
                refuse: plan
                    .prepared(&source.app, &at)
                    .and_then(|prepared| prepared.refusal_renderer()),
                admission: Arc::new(move |app, head| {
                    use busbar_kernel::guest::{Claimant, Matched};
                    let fields: Vec<_> = head
                        .fields
                        .iter()
                        .map(|(name, value)| (name.as_str(), value.as_slice()))
                        .collect();
                    let Matched::Line(line) =
                        owned_guests.matched(&head.method, &head.target, &fields)
                    else {
                        return None;
                    };
                    match &line.claimant {
                        Claimant::Plane(owner) => keys
                            .get(owner)
                            .and_then(|key| app.planes.admission_of(key))
                            .cloned(),
                        Claimant::Need(..) => None,
                        _ if legacy_fallback => app.planes.admission_for(&head.target).cloned(),
                        _ => None,
                    }
                }),
            };
            Ok(busbar_kernel::inbound::Listener {
                ids: Vec::new(),
                guests,
                auths,
                body_limit: source
                    .app
                    .limits
                    .as_ref()
                    .map_or(source.body_limit, |limits| {
                        limits.request_body_max_bytes as u64
                    }),
                app: Arc::clone(&source.app),
                door_refusals: plan
                    .prepared(&source.app, &at)
                    .map(|prepared| prepared.refusals.clone())
                    .unwrap_or_else(|| {
                        plan.refusals
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .get(&at)
                            .cloned()
                            .unwrap_or_default()
                    }),
                signed_ingress: if legacy_fallback {
                    source.signed_ingress.clone()
                } else {
                    Arc::new(|_, _| false)
                },
                scope: Some(scope),
            })
        })
    }
}

// A configured empty data chain is an explicit operator policy, not an empty
// credential requirement. Keep the latter represented by chain_auth([]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum DataChainMode {
    Credentialed,
    OpenRelay,
}

impl DataChainMode {
    fn for_candidate(app: &busbar_kernel::state::App, chain: &[ChainAuth]) -> Self {
        if chain.is_empty() && app.auth.is_open() {
            Self::OpenRelay
        } else {
            Self::Credentialed
        }
    }
}

fn inherited_data_auth(chain: &[ChainAuth], mode: DataChainMode) -> busbar_kernel::guest::LineAuth {
    if mode == DataChainMode::OpenRelay && chain.is_empty() {
        busbar_kernel::guest::LineAuth::None
    } else {
        chain_auth(chain)
    }
}

fn operator_open_claim(mode: DataChainMode, section: &str, flags: u32) -> bool {
    use busbar_contract::abi::plane::{CLAIM_SIGNED_INGRESS, CLAIM_TICKET};
    mode == DataChainMode::OpenRelay
        && section == busbar_contract::section::RESERVED_POOLS_KEY
        && flags & (CLAIM_SIGNED_INGRESS | CLAIM_TICKET) == 0
}

#[cfg(test)]
#[path = "tests/open_relay_composition.rs"]
mod open_relay_composition_tests;

fn chain_auth(data_chain: &[ChainAuth]) -> busbar_kernel::guest::LineAuth {
    let points = data_chain.iter().fold(0, |set, (_, p)| set | p.bits());
    busbar_kernel::guest::LineAuth::Chain(
        data_chain.iter().map(|(name, _)| name.clone()).collect(),
        busbar_contract::abi::auth::AuthPoints(points),
    )
}

fn guest_refusal(listener: &str, refusal: busbar_kernel::guest::GuestRefusal) -> String {
    use busbar_kernel::guest::{GuestRefusal, Line};
    let named = |lines: &[Line]| {
        lines
            .iter()
            .map(|l| format!("{:?} {}", l.claimant, l.route.path))
            .collect::<Vec<_>>()
            .join(", ")
    };
    match refusal {
        GuestRefusal::EqualPrecedence(pair) => format!(
            "{listener}: the claims {:?} {} and {:?} {} meet at an equal precedence",
            pair.0.claimant, pair.0.route.path, pair.1.claimant, pair.1.route.path
        ),
        GuestRefusal::PeerMix(mix) => format!(
            "{listener}: the lines {} need the Peer auth point and the lines {} need a \
             per-request point without it; on one listener, every line that needs a point needs \
             Peer or none does",
            named(mix.0.as_slice()),
            named(mix.1.as_slice())
        ),
        GuestRefusal::Malformed(bad) => format!(
            "{listener}: the line {} matches no request: it breaks {:?} at {}",
            named(std::slice::from_ref(&bad.0)),
            bad.1.rule,
            bad.1.field
        ),
        GuestRefusal::PointNotOffered(line) => format!(
            "{listener}: the line {} needs the auth points {:#x} and its transport offers {:#x}",
            named(std::slice::from_ref(&*line)),
            line.auth.points().bits(),
            line.offered.bits()
        ),
    }
}

const CORE_CLAIMANT: &str = "core";

#[must_use]
pub fn upgrade_carriers(
    transports: &[crate::root::linked::LinkedTransport],
    dropped: &[crate::root::registry::DroppedDoor],
) -> Vec<&'static str> {
    transport_rows(transports, dropped)
        .into_iter()
        .flat_map(|r| r.upgrades)
        .collect()
}

pub type TransportOffer = (&'static str, busbar_contract::abi::auth::AuthPoints);

struct TransportRow {
    claims: Vec<&'static str>,

    upgrades: Vec<&'static str>,

    under: Option<&'static str>,

    offered: busbar_contract::abi::auth::AuthPoints,
}

fn transport_rows(
    transports: &[crate::root::linked::LinkedTransport],
    dropped: &[crate::root::registry::DroppedDoor],
) -> Vec<TransportRow> {
    let linked = transports.iter().map(|t| TransportRow {
        claims: (t.claims)(),
        upgrades: (t.upgrades)(),
        under: (t.composes_over)().first().copied(),
        offered: (t.offered)(),
    });
    let dropped = dropped.iter().map(|d| TransportRow {
        claims: d.claims.clone(),
        upgrades: d.upgrades.clone(),
        under: d.composes_over.first().copied(),
        offered: d.offered,
    });
    linked.chain(dropped).collect()
}

#[must_use]
pub fn transport_offers(
    transports: &[crate::root::linked::LinkedTransport],
    dropped: &[crate::root::registry::DroppedDoor],
) -> Vec<TransportOffer> {
    let rows = transport_rows(transports, dropped);
    let own: Vec<TransportOffer> = rows
        .iter()
        .flat_map(|r| r.claims.iter().map(move |c| (*c, r.offered)))
        .collect();
    rows.iter()
        .flat_map(|r| {
            let under = r.under.map(|l| offered_by(&own, l));
            r.claims.iter().map(move |c| match under {
                Some(under) if r.upgrades.contains(c) => (*c, under),
                _ => (*c, r.offered),
            })
        })
        .collect()
}

fn offered_by(offers: &[TransportOffer], claim: &str) -> busbar_contract::abi::auth::AuthPoints {
    offers
        .iter()
        .find(|(c, _)| *c == claim)
        .map_or_else(crate::root::doors::offers_unstated, |(_, o)| *o)
}

const SESSION_QUEUE: usize = 64;

const SUBTREE: &str = "rest";

const METHODS: [RouteMethod; 5] = [
    RouteMethod::Get,
    RouteMethod::Post,
    RouteMethod::Put,
    RouteMethod::Patch,
    RouteMethod::Delete,
];

fn claim_line(
    instance: &str,
    rung: u32,
    claim: &crate::root::loader::dispatch::kinds::plane::OwnedClaim,
    data_chain: &[ChainAuth],
    upgrades: &[&str],
    offers: &[TransportOffer],
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

            path_form: if exact { PATH_EXACT } else { PATH_PATTERN },
            path: line_path(claim, exact || pattern),
            fields: Vec::new(),
            rung,
        },
        claimant: busbar_kernel::guest::Claimant::Plane(instance.to_string()),
        dialect: u32::from(claim.refusal_dialect),
        auth: line_auth(claim.flags, data_chain),

        upgrade: upgrades
            .contains(&claim.carrier.as_str())
            .then(|| claim.carrier.clone()),
        offered: offered_by(offers, &claim.carrier),
    };
    Ok((line, method))
}

fn line_path(
    claim: &crate::root::loader::dispatch::kinds::plane::OwnedClaim,
    as_written: bool,
) -> String {
    if as_written {
        claim.target.clone()
    } else {
        format!("{}/{{*{SUBTREE}}}", claim.target.trim_end_matches('/'))
    }
}

fn signed_paths(
    claims: &[crate::root::loader::dispatch::kinds::plane::OwnedClaim],
) -> Arc<[String]> {
    use busbar_contract::abi::plane::{CLAIM_RAW_AFFIX, CLAIM_SIGNED_INGRESS};
    claims
        .iter()
        .filter(|c| {
            c.flags & (CLAIM_SIGNED_INGRESS | CLAIM_RAW_AFFIX)
                == CLAIM_SIGNED_INGRESS | CLAIM_RAW_AFFIX
        })
        .map(|c| c.target.clone())
        .collect::<Vec<_>>()
        .into()
}

fn routed(claim: &crate::root::loader::dispatch::kinds::plane::OwnedClaim) -> bool {
    claim.flags & (CLAIM_RAW_AFFIX | CLAIM_ENTRY) == 0
}

fn mount_paths(path: &str) -> Option<Vec<String>> {
    let segs: Vec<&str> = path.split('/').collect();
    let at = segs
        .iter()
        .position(|s| s.starts_with('{') && s.ends_with("+}"))?;
    let prefix = segs[..at].join("/");
    let target = if prefix.is_empty() {
        "/".to_string()
    } else {
        prefix.clone()
    };
    Some(vec![target, format!("{prefix}/{{*{SUBTREE}}}")])
}

type DoorClaim = (usize, u32);

pub fn door_routes(
    served: Served,
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
    data_chain: &[ChainAuth],
    core: &[(String, RouteMethod, RouteAuth)],
) -> Result<Vec<PlaneRouteSpec>, String> {
    door_mounts(served, pin, data_chain, core, &[], &[]).map(|m| m.routes)
}

pub struct DoorMounts {
    pub routes: Vec<PlaneRouteSpec>,

    pub sessions: Vec<busbar_kernel::plane_routes::PlaneSessionSpec>,

    pub refusals: Vec<PlaneRefusalSpec>,

    pub refuse_by_path: Option<busbar_kernel::plane_routes::PlaneRefuseByPathFn>,
}

impl std::fmt::Debug for DoorMounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorMounts")
            .field("routes", &self.routes.len())
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

pub fn door_mounts(
    served: Served,
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
    data_chain: &[ChainAuth],
    core: &[(String, RouteMethod, RouteAuth)],
    upgrades: &[&str],
    offers: &[TransportOffer],
) -> Result<DoorMounts, String> {
    door_mounts_planned(served, pin, data_chain, core, upgrades, offers, None)
}

#[allow(clippy::too_many_arguments)]
fn door_mounts_planned(
    served: Served,
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
    data_chain: &[ChainAuth],
    core: &[(String, RouteMethod, RouteAuth)],
    upgrades: &[&str],
    offers: &[TransportOffer],
    plan: Option<(&ListenerPlan, &busbar_kernel::state::App, &str)>,
) -> Result<DoorMounts, String> {
    use busbar_contract::abi::transport::route::{method_bit, PATH_EXACT, PATH_PATTERN};
    use busbar_kernel::guest::{Claimant, GuestList, LineAuth, Matched};
    use std::collections::HashMap;

    let public = if plan.is_none_or(|(_, _, at)| at == "listen") {
        public_routes(&served)
    } else {
        Vec::new()
    };
    let physical = if let Some((plan, app, at)) = plan {
        if plan.planes.get().is_none() {
            plan.mount_planes(&served, app, upgrades)?;
        }
        Some(
            plan.lists(app)?
                .into_iter()
                .find(|(name, _)| name == at)
                .ok_or_else(|| format!("listener {at} has no guest list"))?
                .1,
        )
    } else {
        None
    };
    let mut upgraded: std::collections::HashSet<DoorClaim> = std::collections::HashSet::new();
    let mut lines = Vec::new();
    let mut doors: Vec<(busbar_kernel::guest::Line, RouteMethod, DoorClaim)> = Vec::new();
    for (p, plane) in served.planes.iter().enumerate() {
        for (i, claim) in plane.snapshot.claims.iter().enumerate() {
            if !routed(claim) || lines::carrier() == Some(claim.carrier.as_str()) {
                continue;
            }
            let rung =
                u32::try_from(i).map_err(|_| format!("{}: too many claims", plane.instance))?;
            let (mut line, method) =
                claim_line(&plane.instance, rung, claim, data_chain, upgrades, offers)?;
            if let Some(guests) = &physical {
                let Some(admitted) = guests.lines().iter().find(|admitted| {
                    admitted.claimant == line.claimant && admitted.route.rung == rung
                }) else {
                    continue;
                };
                line = admitted.clone();
            }
            if line.upgrade.is_some() {
                upgraded.insert((p, rung));
            }
            lines.push(line.clone());
            doors.push((line, method, (p, rung)));
        }
    }

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
                _ => chain_auth(data_chain),
            },
            upgrade: None,

            offered: crate::root::doors::offers_unstated(),
        });
    }
    let guests = match physical {
        Some(guests) => guests,
        None => {
            GuestList::seal(lines).map_err(|refusal| guest_refusal("the data listener", refusal))?
        }
    };
    let post = served.post.clone().unwrap_or_else(|| {
        Arc::new(crate::root::plane_node::NodeEndPost::new(
            crate::root::plane_node::node(),
        ))
    });
    let instances: Vec<String> = served.planes.iter().map(|p| p.instance.clone()).collect();
    let documents = resource_documents(&served);

    let mut mounts: Vec<(String, RouteMethod, RouteAuth, DoorClaim)> = Vec::new();
    let mut of_line: HashMap<(String, u32), (RouteAuth, DoorClaim)> = HashMap::new();
    for (line, method, door) in doors {
        let auth = match line.auth {
            LineAuth::None => RouteAuth::None,
            LineAuth::Chain(..) => RouteAuth::Key,
        };
        let tail = format!("/{{*{SUBTREE}}}");
        let paths = if let Some(paths) = mount_paths(&line.route.path) {
            paths
        } else if line.route.path_form == PATH_EXACT || !line.route.path.ends_with(&tail) {
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

        for path in paths {
            if !mounts.iter().any(|(p, m, ..)| *p == path && *m == method) {
                mounts.push((path, method, auth, door));
            }
        }
        of_line.insert((instances[door.0].clone(), line.route.rung), (auth, door));
    }

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
        claim_doors: plan.map(|(plan, _, _)| Arc::clone(&plan.claim_doors)),
        post,
        pin,
        guests,
        of_line: of_line
            .into_iter()
            .map(|(line, (_, door))| (line, door))
            .collect(),
        frames: Mutex::default(),
    });
    if let Some((plan, _, at)) = plan {
        {
            let mut nests = plan
                .nests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            nests.retain(|routes| routes.strong_count() != 0);
            nests.push(Arc::downgrade(&routes));
        }
        if at == "listen" {
            attach_nest_routes(kernel, Arc::clone(&plan.nests));
        }
    } else {
        attach_nests(kernel, &routes);
    }
    let mut session_mounts: Vec<(String, RouteMethod, RouteAuth, DoorClaim)> = Vec::new();
    let mut sessions = Vec::new();
    let mut requests = Vec::new();
    for mount in mounts {
        let (path, method, auth, door) = mount;
        if !upgraded.contains(&door) {
            requests.push((path, method, auth, door));
            continue;
        }

        if method != RouteMethod::Get {
            continue;
        }
        session_mounts.push((path.clone(), RouteMethod::Get, auth, door));
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

    let signed: Vec<Arc<[String]>> = routes
        .served
        .planes
        .iter()
        .map(|p| signed_paths(&p.snapshot.claims))
        .collect();
    let refusals: Vec<PlaneRefusalSpec> = requests
        .iter()
        .chain(&session_mounts)
        .filter(|(_, _, auth, _)| matches!(auth, RouteAuth::Key))
        .map(|(path, method, _, (plane, claim))| {
            let (routes, plane, claim) = (Arc::clone(&routes), *plane, *claim);

            let ticket_prefix = {
                let served = &routes.served.planes[plane];
                let takes = served
                    .snapshot
                    .claims
                    .get(claim as usize)
                    .is_some_and(|c| c.flags & busbar_contract::abi::plane::CLAIM_TICKET != 0);
                takes
                    .then(|| served.kernel.ticket_prefix_of(&served.instance))
                    .flatten()
            };
            PlaneRefusalSpec {
                route: busbar_kernel::plane_routes::DoorRouteId {
                    path: path.clone(),
                    method: *method,
                },
                ticket_prefix,
                signed_ingress: Arc::clone(&signed[plane]),
                refuse: Arc::new(move |reason: ReasonCode, target: &str| {
                    let served = &routes.served.planes[plane];
                    let dialect = served
                        .snapshot
                        .claims
                        .get(claim as usize)
                        .map_or(0, |c| u32::from(c.refusal_dialect));
                    let rendered =
                        served
                            .driver
                            .refuse_unitless(reason, dialect, target.as_bytes());
                    stated(
                        (rendered.status, rendered.fields),
                        Body::from(rendered.body),
                    )
                }),
            }
        })
        .collect();

    let entries: Vec<Arc<EntrySpans>> = routes
        .served
        .planes
        .iter()
        .map(|p| {
            Arc::new(EntrySpans::of(p.snapshot.claims.iter().map(|c| {
                (
                    c.verb.as_str(),
                    c.target.as_str(),
                    c.flags,
                    c.arrival_span.as_str(),
                )
            })))
        })
        .collect();

    let refuse_by_path: busbar_kernel::plane_routes::PlaneRefuseByPathFn = {
        let routes = Arc::clone(&routes);
        Arc::new(move |r: &busbar_kernel::plane_routes::KernelRefusal<'_>| {
            let line = match r.selected_line {
                Some(selected) => routes.guests.lines().iter().find(|line| {
                    line.claimant == selected.claimant && line.route == selected.route
                })?,
                None => match routes.guests.matched("", r.path, &[]) {
                    Matched::MethodMiss(line) => line,
                    _ => return None,
                },
            };
            let Claimant::Plane(instance) = &line.claimant else {
                return None;
            };
            let (plane, _) = *routes.of_line.get(&(instance.clone(), line.route.rung))?;
            let rendered = routes.served.planes[plane].driver.refuse_kernel(
                r.reason,
                u32::from(r.status),
                r.text,
                line.dialect,
                r.target.as_bytes(),
            )?;
            Some(stated(
                (rendered.status, rendered.fields),
                Body::from(rendered.body),
            ))
        })
    };
    let routes_of = requests
        .into_iter()
        .map(|(path, method, auth, (plane, claim))| {
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

            let catalog = routes.served.planes[plane]
                .snapshot
                .claims
                .get(claim as usize)
                .is_some_and(|c| c.flags & busbar_contract::abi::plane::CLAIM_CATALOG != 0);
            if catalog {
                let routes = Arc::clone(&routes);
                return PlaneRouteSpec {
                    path,
                    method,
                    auth,
                    handler: Arc::new(move |ctx: PlaneReqCtx| -> PlaneRouteFuture {
                        let routes = Arc::clone(&routes);
                        Box::pin(async move {
                            match DoorRequest::of(ctx) {
                                Some(req) => routes.catalog(plane, &req),
                                None => stated(
                                    (refusal_status(ReasonCode::PlanePanic), Vec::new()),
                                    Body::empty(),
                                ),
                            }
                        })
                    }),
                };
            }
            let entry = Arc::clone(&entries[plane]);
            let routes = Arc::clone(&routes);
            PlaneRouteSpec {
                path,
                method,
                auth,
                handler: Arc::new(move |ctx: PlaneReqCtx| -> PlaneRouteFuture {
                    let routes = Arc::clone(&routes);
                    let entry = Arc::clone(&entry);
                    Box::pin(async move {
                        match DoorRequest::of(ctx) {
                            Some(req) => {
                                use tracing::Instrument as _;
                                let span = {
                                    let field = |name: &str| req.field(name);
                                    entry.open(claim, req.method.as_str(), req.uri.path(), field)
                                };
                                routes.answer(plane, claim, req).instrument(span).await
                            }
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

    if plan.is_none() {
        crate::root::inbound::stage(routes.guests.clone(), refusals.clone());
    }
    Ok(DoorMounts {
        routes: routes_of,
        sessions,
        refusals,
        refuse_by_path: Some(refuse_by_path),
    })
}

pub(crate) fn line_routes(
    served: Served,
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
) -> Result<Arc<DataRoutes>, String> {
    use busbar_kernel::guest::GuestList;
    let mut lines_of = Vec::new();
    let mut of_line = std::collections::HashMap::new();
    for (p, plane) in served.planes.iter().enumerate() {
        for (i, claim) in plane.snapshot.claims.iter().enumerate() {
            if !routed(claim) || lines::carrier() == Some(claim.carrier.as_str()) {
                continue;
            }
            let rung =
                u32::try_from(i).map_err(|_| format!("{}: too many claims", plane.instance))?;
            let (line, _) = claim_line(&plane.instance, rung, claim, &[], &[], &[])?;
            of_line.insert((plane.instance.clone(), rung), (p, rung));
            lines_of.push(line);
        }
    }
    let guests =
        GuestList::seal(lines_of).map_err(|refusal| guest_refusal("the line carrier", refusal))?;
    let post = served.post.clone().unwrap_or_else(|| {
        Arc::new(crate::root::plane_node::NodeEndPost::new(
            crate::root::plane_node::node(),
        ))
    });
    let kernel = served.planes.first().map(|p| Arc::clone(&p.kernel));
    let routes = Arc::new(DataRoutes {
        served,
        claim_doors: None,
        post,
        pin,
        guests,
        of_line,
        frames: Mutex::default(),
    });
    if let Some(nests) = &routes.served.nests {
        nests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::downgrade(&routes));
        attach_nest_routes(kernel, Arc::clone(nests));
    } else {
        attach_nests(kernel, &routes);
    }
    Ok(routes)
}

fn attach_nests(kernel: Option<Arc<KernelServices>>, routes: &Arc<DataRoutes>) {
    attach_nest_routes(kernel, Arc::new(Mutex::new(vec![Arc::downgrade(routes)])));
}

fn attach_nest_routes(kernel: Option<Arc<KernelServices>>, routes: NestRoutes) {
    if let (Some(kernel), Ok(runtime)) = (kernel, tokio::runtime::Handle::try_current()) {
        let detached = busbar_kernel::detached::worker_detached();
        let _attached = kernel.attach_nest(Arc::new(DoorNests {
            routes,
            runtime,
            detached,
        }));
    }
}

fn public_routes(served: &Served) -> Vec<PlaneRouteSpec> {
    let tables = &served.tables;
    served
        .planes
        .iter()
        .flat_map(|p| p.snapshot.admin_routes.iter())
        .filter(|r| r.flags & busbar_contract::abi::plane::ROUTE_PUBLIC != 0)
        .filter_map(|r| {
            let method = METHODS
                .into_iter()
                .find(|m| m.as_str().eq_ignore_ascii_case(&r.verb))?;
            Some(PlaneRouteSpec {
                path: r.target.clone(),
                method,
                auth: RouteAuth::None,
                handler: Arc::new({
                    let tables = tables.clone();
                    move |ctx: PlaneReqCtx| -> PlaneRouteFuture {
                        let tables = tables.clone();
                        Box::pin(async move {
                            let target = ctx
                                .uri
                                .path_and_query()
                                .map_or_else(|| ctx.path.clone(), |pq| pq.as_str().to_string());
                            tables
                                .answer_public(
                                    ctx.method.as_str(),
                                    &ctx.path,
                                    &target,
                                    &ctx.headers,
                                    ctx.body,
                                )
                                .await
                        })
                    }
                }),
            })
        })
        .collect()
}

struct ResourceDocument {
    resource: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
}

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
        let facts: serde_json::Value = match snapshot.resource_facts.as_deref() {
            Some(bytes) => serde_json::from_slice(bytes).unwrap_or_else(|error| {
                tracing::warn!(plane = %plane.instance, error = %error,
                    "plane resource facts are not JSON; protected-resource metadata uses empty facts");
                serde_json::Value::Null
            }),
            None => serde_json::Value::Null,
        };
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

impl DoorRequest {
    fn field(&self, name: &str) -> Option<&str> {
        match self.headers.get(name) {
            Some(value) => value.to_str().ok(),
            None => self
                .consumed_fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, scheme)| scheme.as_str()),
        }
    }

    fn of(ctx: PlaneReqCtx) -> Option<Self> {
        let app = match ctx.engine.downcast::<busbar_kernel::state::App>() {
            Ok(app) => app,
            Err(engine) => engine
                .downcast::<busbar_kernel::state::AppHandle>()
                .ok()?
                .load(),
        };

        let mut headers = ctx.headers;
        headers.remove(busbar_contract::abi::host::service::CARRIER_SESSION_FIELD);
        Some(DoorRequest {
            method: axum::http::Method::from_bytes(ctx.method.as_str().as_bytes()).ok()?,
            uri: ctx.uri,
            headers,
            body: ctx.body,
            gov: ctx.gov.unwrap_or_default(),
            credential: ctx.caller_credential,
            ticket: ctx.ticket,
            app,
            scheme: ctx.scheme,
            consumed_fields: ctx.consumed_fields,
        })
    }
}

type BoundParent = (
    Arc<busbar_kernel::state::App>,
    crate::root::plane_node::Parent,
);

impl DataRoutes {
    fn catalog(&self, plane: usize, req: &DoorRequest) -> Response {
        let names = busbar_kernel::endpoints::catalog_names(&req.app, &req.gov);
        let target = req
            .uri
            .path_and_query()
            .map_or_else(|| req.uri.path().to_string(), |t| t.as_str().to_string());
        let head: Vec<(Vec<u8>, Vec<u8>)> = req
            .headers
            .iter()
            .filter(|(n, _)| !NEVER_KEPT.contains(&n.as_str()))
            .map(|(n, v)| (n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        let rendered = self.served.planes[plane].driver.catalog_unitless(
            req.method.as_str().as_bytes(),
            target.as_bytes(),
            &head,
            &names,
        );
        match rendered {
            Some(r) => stated((r.status, r.fields), Body::from(r.body)),
            None => stated(
                (refusal_status(ReasonCode::PlanePanic), Vec::new()),
                Body::empty(),
            ),
        }
    }

    async fn open_session(
        self: Arc<Self>,
        plane: usize,
        claim: u32,
        req: DoorRequest,
    ) -> busbar_kernel::plane_routes::SessionAnswer {
        use busbar_kernel::plane_routes::{SessionAnswer, SessionPipe};
        let (door, arrival, _) = self.arrived(plane, claim, req);
        let (from_caller, from_rx) = mpsc::channel(SESSION_QUEUE);
        let (to_tx, to_caller) = mpsc::channel(SESSION_QUEUE);
        let caller = PipeCaller {
            from: tokio::sync::Mutex::new(from_rx),
            to: to_tx,
        };
        let (verdict, said) = oneshot::channel();
        busbar_kernel::detached::spawn_detached(self.session(
            door,
            ClosingCaller::new(caller),
            arrival,
            verdict,
            Attach::switched(),
        ));
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

    async fn session<C: SessionCaller + Send + Sync + 'static>(
        self: Arc<Self>,
        door: SessionDoor,
        caller: C,
        arrival: Arrival,
        verdict: oneshot::Sender<Result<(), Option<Rendered>>>,
        mut attach: Attach,
    ) {
        use busbar_kernel::teller::SessionOpen;
        let served = &self.served.planes[door.plane];
        if let Some(refused) = journal_refused(served, &self.post, &arrival) {
            let _ = verdict.send(Err(Some(refused)));
            return;
        }
        let live = served.live.current();
        let node = self.post.node();
        let unit = node.mint();
        let carrier_end = CarrierEnd {
            unit: unit.get(),
            ended: attach.ended.take(),
        };
        let arrived = node.arrived();
        self.frames_lock().insert(unit.get(), Arc::clone(&door.app));
        let _frame = UnitFrame {
            routes: &self,
            unit: unit.get(),
        };
        let steps = DoorSteps::new(
            &live.facts,
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
                ticket: door.ticket,
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
        let Some((opened, ctx, slot)) = node
            .open_borrowed(
                unit,
                arrived,
                &door.principal,
                &self.post,
                &units,
                (self.pin)(),
                live.facts.audit_kind,
            )
            .await
        else {
            let _ = verdict.send(Err(None));
            return;
        };
        let admitted = match opened {
            SessionOpen::Admitted {
                route,
                destinations,
            } => match units.open_hooks(&route, &ctx).await {
                Err(reason) => {
                    self.post.stopped(unit, reason);
                    None
                }
                Ok(()) => match attach.admitted.take().map(|admitted| admitted(unit.get())) {
                    Some(Err(reason)) => {
                        tracing::warn!(plane = %served.instance, unit = unit.get(), error = ?reason,
                            "session carrier could not attach to its admitted unit");
                        self.post.stopped(unit, ReasonCode::HandoffMismatch);
                        None
                    }
                    None | Some(Ok(())) => Some((route, destinations)),
                },
            },
            SessionOpen::Refused => None,
        };
        let status = match admitted {
            Some((route, destinations)) => {
                let _ = verdict.send(Ok(()));
                let _ended = units.session(&route, &ctx, &destinations).await;
                attach.answered
            }
            None => {
                let rendered = units.take_rendered();
                let status = rendered
                    .as_ref()
                    .map_or_else(|| refusal_status(ReasonCode::PlanePanic), |r| r.status);
                let _ = verdict.send(Err(rendered));
                status
            }
        };

        drop(carrier_end);

        self.post
            .reported(unit, report_of(&served.money, unit, &live.facts));
        slot.finish(&self.post);
        served.money.settle_end(unit, status);
    }

    async fn open_datagram(
        self: Arc<Self>,
        (framer, carrier): (Arc<dyn busbar_core_connector::framer::FramerDoor>, String),
        door: SessionDoor,
        arrival: Arrival,
    ) -> Response {
        let doors = self
            .claim_doors
            .as_ref()
            .and_then(|doors| doors.get())
            .unwrap_or(&self.served.claim_doors);
        let Some(claim_door) = doors.get(&carrier) else {
            return stated(
                (refusal_status(ReasonCode::NoDestination), Vec::new()),
                Body::empty(),
            );
        };
        let opened = match serve_datagram::Opened::open(&claim_door, framer, &arrival.body) {
            Ok(o) => o,
            Err(_) => {
                return stated(
                    (refusal_status(ReasonCode::DecodeFailed), Vec::new()),
                    Body::empty(),
                )
            }
        };
        let serve_datagram::Opened {
            description,
            caller,
            head,
            joining,
        } = opened;

        let mut opening = DatagramOpening::new(joining);
        let admitted = opening.admission();
        let ended = Box::new(|unit: u64| crate::root::connector::the().unpair(unit))
            as Box<dyn FnOnce(u64) + Send>;
        let (verdict, said) = oneshot::channel();
        let attach = Attach {
            answered: CREATED,
            admitted: Some(admitted),
            ended: Some(ended),
        };
        busbar_kernel::detached::spawn_detached(self.session(
            door,
            ClosingCaller::new(caller),
            arrival,
            verdict,
            attach,
        ));
        match said.await {
            Ok(Ok(())) => match serve_datagram::plane_head(head, OPEN_HEAD_WAIT).await {
                Some((status, fields)) => {
                    let response = stated((status, fields), description.into_body());
                    opening.transfer();
                    response
                }
                None => stated(
                    (refusal_status(ReasonCode::PlanePanic), Vec::new()),
                    Body::empty(),
                ),
            },
            Ok(Err(Some(rendered))) => stated(
                (rendered.status, rendered.fields),
                Body::from(rendered.body),
            ),
            Ok(Err(None)) | Err(_) => stated(
                (refusal_status(ReasonCode::PlanePanic), Vec::new()),
                Body::empty(),
            ),
        }
    }

    fn arrived(&self, plane: usize, claim: u32, req: DoorRequest) -> (SessionDoor, Arrival, Bytes) {
        let DoorRequest {
            method,
            uri,
            headers,
            body,
            gov,
            credential,
            ticket,
            app,
            scheme: _,
            consumed_fields: _,
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
            body: body.clone(),
        };
        let principal = match gov.key() {
            Some(key) => PrincipalId::new(key.id.as_str()),
            None => PrincipalId::new(AuthPrincipal(None).actor_id()),
        };

        let pools_plane = self.served.planes[plane].live.served_facts.section
            == busbar_contract::section::RESERVED_POOLS_KEY;
        let open = (pools_plane && app.auth.is_open())
            || self.served.planes[plane]
                .snapshot
                .claims
                .get(claim as usize)
                .is_some_and(|c| c.flags & CLAIM_OPEN != 0);
        let key = gov.key.clone();
        let door = SessionDoor {
            plane,
            app,
            principal,
            key,
            open,
            credential,
            ticket,
        };
        (door, arrival, body)
    }

    async fn answer(self: Arc<Self>, plane: usize, claim: u32, req: DoorRequest) -> Response {
        let scheme = req.scheme;
        let (door, arrival, body) = self.arrived(plane, claim, req);

        let framed = self.served.planes[plane]
            .snapshot
            .claims
            .get(claim as usize)
            .and_then(|c| self.framer_for(&c.carrier).map(|d| (d, c.carrier.as_str())));

        let datagram_carrier = framed
            .as_ref()
            .filter(|(d, _)| d.facts().datagram)
            .map(|(d, c)| (Arc::clone(d), (*c).to_owned()));
        if let Some(carried) = datagram_carrier {
            return self.open_datagram(carried, door, arrival).await;
        }
        let SessionDoor {
            app,
            principal,
            key,
            open,
            credential,
            ticket,
            ..
        } = door;

        if let Some((door, carrier)) =
            framed.and_then(|(d, c)| framed_by(c, |_| Some(Arc::clone(&d))).map(|door| (door, c)))
        {
            let head: Vec<(String, Vec<u8>)> = arrival
                .fields
                .iter()
                .map(|(n, v)| (String::from_utf8_lossy(n).into_owned(), v.clone()))
                .collect();
            let target = String::from_utf8_lossy(&arrival.target).into_owned();
            let Ok(mut stream) = busbar_core_connector::framed_stream::FramedStream::open(
                door, carrier, &target, &head, scheme,
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
                    return match stream.refuse(why.error.as_bytes(), status, false) {
                        Ok(block) => serve_framed::whole(status, &block),
                        Err(_) => stated((status, Vec::new()), Body::empty()),
                    };
                }
            };
            let (arrival, inner, reply) = deframed_arrival(arrival, &messages);
            let stream = serve_framed::shared(stream);
            let (trailers, trailed) = oneshot::channel();
            let caller = serve_framed::FramedCaller::new(inner, Arc::clone(&stream), trailers);
            let unit = async move {
                let caller = caller;
                self.drive(
                    plane,
                    app,
                    (principal, key, credential, ticket),
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
                (principal, key, credential, ticket),
                open,
                &caller,
                arrival,
                None,
            )
            .await
        };
        reply.answer(Box::pin(unit)).await
    }

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

    fn parent_of(&self, nest: &busbar_kernel::host_services::Nest) -> Option<BoundParent> {
        let app = self.frames_lock().get(&nest.parent).cloned()?;
        let parent = self
            .post
            .node()
            .parent(busbar_contract::UnitKey::new(nest.parent))?;
        Some((app, parent))
    }

    async fn nested(
        self: Arc<Self>,
        nest: busbar_kernel::host_services::Nest,
        (app, parent): BoundParent,
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
        let principal = match nest.principal.as_deref() {
            Some(key) => PrincipalId::new(key.id.as_str()),
            None => PrincipalId::new(AuthPrincipal(None).actor_id()),
        };
        let pools_plane = self.served.planes[plane].live.served_facts.section
            == busbar_contract::section::RESERVED_POOLS_KEY;
        let open = (pools_plane && app.auth.is_open())
            || self.served.planes[plane]
                .snapshot
                .claims
                .get(claim as usize)
                .is_some_and(|c| c.flags & CLAIM_OPEN != 0);
        let arrival = Arrival {
            claim,
            method: nest.ask.verb.into_bytes(),
            target: nest.ask.target.into_bytes(),
            fields: Vec::new(),
            body: bytes::Bytes::from(nest.ask.body),
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
                    (principal, key, None, None),
                    open,
                    &caller,
                    arrival,
                    Some(nesting),
                )
                .await
        };
        let response = reply.answer_nested(Box::pin(unit)).await;
        let (parts, body) = response.into_parts();
        let Ok(body) = axum::body::to_bytes(body, NEST_REPLY_MAX).await else {
            return NestReply::Failed(NEST_UNREAD);
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

    #[allow(clippy::too_many_arguments)]
    async fn drive<C: SessionCaller + Stated + Send + Sync>(
        &self,
        plane: usize,
        app: Arc<busbar_kernel::state::App>,
        (principal, key, credential, ticket): UnitCaller,
        open: bool,
        caller: &C,
        arrival: Arrival,
        nesting: Option<Nesting>,
    ) -> Option<Rendered> {
        let served = &self.served.planes[plane];
        if let Some(refused) = journal_refused(served, &self.post, &arrival) {
            return Some(refused);
        }

        let live = served.live.current();
        let started = std::time::Instant::now();
        let claim = arrival.claim;
        let app_for_metrics = Arc::clone(&app);
        let node = self.post.node();
        let unit = node.mint();
        let arrived = node.arrived();

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
                ticket,
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
        let held = Arc::clone(&live);
        let late: crate::root::linked::node::Late =
            Box::new(move || report_of(&money, unit, &held.facts));

        let ended = node
            .drive_borrowed(
                unit,
                arrived,
                &principal,
                &self.post,
                &units,
                late,
                (self.pin)(),
                nesting.as_ref().map(|n| &n.parent),
                live.facts.audit_kind,
            )
            .await;

        let downgraded = steps.downgraded();

        caller.ended(ended);
        let rendered = units.take_rendered();
        let status = rendered
            .as_ref()
            .map(|r| r.status)
            .or_else(|| caller.stated())
            .unwrap_or_else(|| refusal_status(ReasonCode::PlanePanic));

        served.money.settle_end_as(
            unit,
            busbar_kernel::plane_driver::UnitEnd {
                caller_status: status,
                cut: steps.stream_cut(),
            },
        );

        if live.facts.plane.is_empty() {
            let decoded = units.decoded();
            let counted = decoded.is_some()
                || units.declined_unsupported_action()
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
                let pool = downgraded
                    .or_else(|| {
                        decoded
                            .and_then(|d| d.pool)
                            .map(|p| String::from_utf8_lossy(&p).into_owned())
                    })
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

fn journal_refused(
    served: &ServedPlane,
    post: &crate::root::plane_node::NodeEndPost,
    arrival: &Arrival,
) -> Option<Rendered> {
    let why = post.node().journal_refusal()?;
    let status = refusal_status(ReasonCode::DurabilityUnavailable);
    let dialect = served
        .snapshot
        .claims
        .get(arrival.claim as usize)
        .map_or(0, |c| u32::from(c.refusal_dialect));
    Some(
        served
            .driver
            .refuse_kernel(
                ReasonCode::DurabilityUnavailable,
                status,
                &why,
                dialect,
                &arrival.target,
            )
            .unwrap_or_else(|| Rendered {
                status,
                fields: Vec::new(),
                body: why.into_bytes(),
            }),
    )
}

struct Nesting {
    parent: crate::root::plane_node::Parent,
    depth: u32,
}

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

struct DoorFar<'d, 's> {
    egress: Option<&'d Egress>,

    shown: Option<&'d crate::root::model_egress::ModelShown>,
    steps: &'d DoorSteps<'s>,
    unit: busbar_contract::UnitKey,

    credential: Option<busbar_contract::redacted::Secret<Vec<u8>>>,
    far: OnceLock<Option<EgressFarEnd<'d>>>,
}

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

                    wants_stream: self.steps.streamed(),
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

fn spent() -> Pick {
    Pick::Exhausted {
        status: refusal_status(ReasonCode::BreakerOpen),
        retry_after: None,
        detail: busbar_kernel_egress::wire::DETAIL_OVERLOADED,
    }
}

impl FarEnd for DoorFar<'_, '_> {
    fn deadline_ns(&self, now_ns: u64) -> u64 {
        self.far().map_or(0, |far| far.deadline_ns(now_ns))
    }

    fn scope(&self, _token: &Pass<Route>) -> Option<RoutedScope> {
        let routed = self.steps.routed()?;
        let container = match &routed {
            (label, _) if !label.is_empty() => label.clone(),
            (_, members) => members.first().cloned().unwrap_or_default(),
        };
        Some(RoutedScope {
            pool: egress_pool(self.steps.plane(), &routed),
            container,
        })
    }

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

    fn judged(&self, token: &Pass<Route>, fault: u8) {
        if let Some(far) = self.far() {
            far.judged(token, fault);
        }
    }

    fn judged_stating(&self, token: &Pass<Route>, fault: u8, reason: Option<&str>) {
        if let Some(far) = self.far() {
            far.judged_stating(token, fault, reason);
        }
    }

    fn taken(&self, token: &Pass<Route>) {
        if let Some(far) = self.far() {
            far.taken(token);
        }
    }

    async fn write(&self, token: &Pass<Route>, request: OutboundRequest) -> bool {
        match self.far() {
            Some(far) => far.write(token, request).await,
            None => false,
        }
    }

    fn stated(&self, token: &Pass<Route>, labels: busbar_kernel_egress::ports::StatedLabels) {
        if let Some(far) = self.far() {
            far.stated(token, labels);
        }
    }

    fn member_wait(&self, token: &Pass<Route>, member: &str) -> Option<u32> {
        self.far().and_then(|far| far.member_wait(token, member))
    }

    fn remaining(&self, token: &Pass<Route>) -> Option<usize> {
        self.far().and_then(|far| far.remaining(token))
    }

    fn failure(&self, token: &Pass<Route>) -> Option<&'static str> {
        self.far().and_then(|far| far.failure(token))
    }

    fn attempt_span(&self, token: &Pass<Route>) -> tracing::Span {
        self.far()
            .map_or_else(tracing::Span::none, |far| far.attempt_span(token))
    }

    fn unsent(&self, token: &Pass<Route>) -> Option<busbar_contract::abi::plane::RefusalCode> {
        self.far().and_then(|far| far.unsent(token))
    }

    fn candidates(&self, token: &Pass<Route>) -> Option<busbar_kernel::plane_driver::Candidates> {
        let mut candidates = self.far()?.candidates(token)?;
        for candidate in &mut candidates.members {
            candidate.route_cost = self.steps.route_cost(&candidate.model);
        }
        Some(candidates)
    }

    fn constrain(&self, token: &Pass<Route>, constraint: busbar_kernel::plane_driver::Constraint) {
        if let Some(far) = self.far() {
            far.constrain(token, constraint);
        }
    }
}

const SWITCHED: u32 = 101;

const CREATED: u32 = 201;

const OPEN_HEAD_WAIT: std::time::Duration = busbar_core_connector::compose::DEFAULT_OPEN_TIMEOUT;

struct Attach {
    answered: u32,
    admitted: Option<OnAdmitted>,
    ended: Option<Box<dyn FnOnce(u64) + Send>>,
}

type OnAdmitted = Box<dyn FnOnce(u64) -> Result<(), String> + Send>;

struct DatagramOpening {
    state: Arc<Mutex<DatagramOpeningState>>,
    transferred: bool,
}

struct DatagramOpeningState {
    joining: Option<serve_datagram::Joining>,
    unit: Option<u64>,
    abandoned: bool,
}

const DATAGRAM_OPEN_ABANDONED: &str = "the datagram opening was abandoned";
const DATAGRAM_ALREADY_ADMITTED: &str = "the datagram opening was admitted twice";

impl DatagramOpening {
    fn new(joining: serve_datagram::Joining) -> Self {
        Self {
            state: Arc::new(Mutex::new(DatagramOpeningState {
                joining: Some(joining),
                unit: None,
                abandoned: false,
            })),
            transferred: false,
        }
    }

    fn admission(&self) -> OnAdmitted {
        let state = Arc::clone(&self.state);
        Box::new(move |unit| Self::admit_with(&state, unit, |joining| joining.admit(unit)))
    }

    fn admit_with(
        state: &Mutex<DatagramOpeningState>,
        unit: u64,
        join: impl FnOnce(serve_datagram::Joining) -> Result<(), String>,
    ) -> Result<(), String> {
        let joining = {
            let mut state = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.abandoned {
                return Err(DATAGRAM_OPEN_ABANDONED.to_owned());
            }
            state
                .joining
                .take()
                .ok_or_else(|| DATAGRAM_ALREADY_ADMITTED.to_owned())?
        };

        join(joining)?;
        let abandoned = {
            let mut state = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.abandoned {
                true
            } else {
                state.unit = Some(unit);
                false
            }
        };
        if abandoned {
            crate::root::connector::the().unpair(unit);
            Err(DATAGRAM_OPEN_ABANDONED.to_owned())
        } else {
            Ok(())
        }
    }

    fn transfer(&mut self) {
        self.transferred = true;
    }
}

impl Drop for DatagramOpening {
    fn drop(&mut self) {
        if self.transferred {
            return;
        }
        let (joining, unit) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.abandoned = true;
            (state.joining.take(), state.unit.take())
        };
        drop(joining);
        if let Some(unit) = unit {
            crate::root::connector::the().unpair(unit);
        }
    }
}

struct CarrierEnd {
    unit: u64,
    ended: Option<Box<dyn FnOnce(u64) + Send>>,
}

impl Drop for CarrierEnd {
    fn drop(&mut self) {
        if let Some(ended) = self.ended.take() {
            ended(self.unit);
        }
    }
}

impl Attach {
    fn switched() -> Self {
        Attach {
            answered: SWITCHED,
            admitted: None,
            ended: None,
        }
    }
}

struct SessionDoor {
    plane: usize,
    app: Arc<busbar_kernel::state::App>,
    principal: PrincipalId,
    key: Option<Arc<busbar_contract::records::VirtualKey>>,
    open: bool,

    credential: Option<busbar_contract::redacted::Secret<Vec<u8>>>,

    ticket: Option<Vec<u8>>,
}

struct ClosingCaller<C> {
    inner: C,
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
}

impl<C> ClosingCaller<C> {
    fn new(inner: C) -> Self {
        Self {
            inner,
            shutdown: busbar_kernel::detached::worker_shutdown(),
        }
    }
}

impl<C: SessionCaller> CallerEnd for ClosingCaller<C> {
    fn head(&self, status: u32, fields: HeadFields) {
        self.inner.head(status, fields);
    }

    async fn write(&self, bytes: &[u8]) -> bool {
        tokio::select! {
            biased;
            () = busbar_kernel::detached::shutdown_fired(self.shutdown.clone()) => false,
            written = self.inner.write(bytes) => written,
        }
    }

    async fn write_text(&self, bytes: &[u8]) -> bool {
        tokio::select! {
            biased;
            () = busbar_kernel::detached::shutdown_fired(self.shutdown.clone()) => false,
            written = self.inner.write_text(bytes) => written,
        }
    }

    async fn write_piece(&self, bytes: &[u8], text: bool, message_end: bool) -> bool {
        tokio::select! {
            biased;
            () = busbar_kernel::detached::shutdown_fired(self.shutdown.clone()) => false,
            written = self.inner.write_piece(bytes, text, message_end) => written,
        }
    }
}

impl<C: SessionCaller> SessionCaller for ClosingCaller<C> {
    async fn read_owned(&self) -> Option<busbar_kernel::plane_driver::SessionInput> {
        tokio::select! {
            biased;
            () = busbar_kernel::detached::shutdown_fired(self.shutdown.clone()) => None,
            piece = self.inner.read_owned() => piece,
        }
    }

    async fn read(&self) -> Option<Vec<u8>> {
        tokio::select! {
            biased;
            () = busbar_kernel::detached::shutdown_fired(self.shutdown.clone()) => None,
            piece = self.inner.read() => piece,
        }
    }
}

struct PipeCaller {
    from: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    to: mpsc::Sender<busbar_kernel::plane_routes::SessionOut>,
}

impl CallerEnd for PipeCaller {
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

impl busbar_kernel::plane_driver::SessionCaller for PipeCaller {
    async fn read(&self) -> Option<Vec<u8>> {
        self.from.lock().await.recv().await
    }
}

fn deframed_arrival(
    arrival: Arrival,
    messages: &[Vec<u8>],
) -> (Arrival, IngressCaller, IngressReply) {
    let deframed = Bytes::from(messages.concat());
    let arrival = Arrival {
        body: deframed.clone(),
        ..arrival
    };
    let (caller, reply) = IngressCaller::arriving(deframed);
    (arrival, caller, reply)
}

/// THE CALLER'S SIDE OF A DRIVEN UNIT over today's hyper ingress.
///
/// The head goes to the handler once; the bytes go into the response body through a channel of one
/// piece, so a `write` resolves only once the body has taken the piece before it (the caller's side
/// was writable). A body the server dropped (the caller went away) answers `false`.
///
/// A unit served as a duplex session (`ROUTE_SESSION`) uses this caller
/// side as its session's caller leg: its read yields the
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

type Head = (u32, HeadFields);

/// The handler's end of an [`IngressCaller`]: the reply, once the unit states its head.
#[derive(Debug)]
pub struct IngressReply {
    head: oneshot::Receiver<Head>,
    body: mpsc::Receiver<Bytes>,
    /// The answer's trailers, where a framer renders a close after its body.
    trailers: Option<oneshot::Receiver<axum::http::HeaderMap>>,
}

/// Ordinary whole replies retain their buffering; nested replies are collected only by the
/// existing nesting bound, while their producer is still running.
#[derive(Clone, Copy)]
enum WholeReplies {
    Collect,
    Stream,
}

impl IngressCaller {
    #[must_use]
    pub fn new() -> (Self, IngressReply) {
        Self::arriving(Bytes::new())
    }

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

    #[must_use]
    pub fn stated(&self) -> Option<u32> {
        Some(self.stated.load(std::sync::atomic::Ordering::Acquire)).filter(|s| *s != 0)
    }
}

pub(crate) trait Stated {
    fn stated(&self) -> Option<u32>;

    fn ended(&self, _outcome: Option<busbar_contract::caps::Outcome>) {}
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
            let _gone = sender.send((status, fields));
        }
    }

    async fn write(&self, bytes: &[u8]) -> bool {
        self.body.send(Bytes::copy_from_slice(bytes)).await.is_ok()
    }
}

impl SessionCaller for IngressCaller {
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
    pub async fn response(self) -> Option<Response> {
        let head = self.head.await.ok()?;
        Some(stated(
            head,
            Body::new(ReplyBody(self.body, None, self.trailers)),
        ))
    }

    #[must_use]
    pub fn with_trailers(mut self, trailers: oneshot::Receiver<axum::http::HeaderMap>) -> Self {
        self.trailers = Some(trailers);
        self
    }

    pub async fn answer(self, unit: DrivenUnit) -> Response {
        self.answer_collecting(unit, WholeReplies::Collect).await
    }

    async fn answer_nested(self, unit: DrivenUnit) -> Response {
        self.answer_collecting(unit, WholeReplies::Stream).await
    }

    async fn answer_collecting(self, unit: DrivenUnit, whole: WholeReplies) -> Response {
        self.answer_with_collection(unit, whole, |rendered| match rendered {
            Some(r) => stated((r.status, r.fields), Body::from(r.body)),
            None => stated(
                (refusal_status(ReasonCode::PlanePanic), Vec::new()),
                Body::empty(),
            ),
        })
        .await
    }

    pub async fn answer_with(
        self,
        unit: DrivenUnit,
        unrendered: impl FnOnce(Option<Rendered>) -> Response,
    ) -> Response {
        self.answer_with_collection(unit, WholeReplies::Collect, unrendered)
            .await
    }

    async fn answer_with_collection(
        self,
        mut unit: DrivenUnit,
        whole: WholeReplies,
        unrendered: impl FnOnce(Option<Rendered>) -> Response,
    ) -> Response {
        let IngressReply {
            mut head,
            body,
            mut trailers,
        } = self;
        let first = tokio::select! {
            biased;
            h = &mut head => Ok(h.ok()),
            rendered = &mut unit => Err(rendered),
        };
        let rendered = match first {
            Ok(Some(h)) if matches!(whole, WholeReplies::Collect) && whole_answer(&h.1) => {
                let whole = collect(body, unit).await;
                return stated(unlengthed(h), Body::from(whole));
            }

            Ok(Some(h)) => {
                let h = if whole_answer(&h.1) { unlengthed(h) } else { h };
                if let Some(block) = closed_before_body(&body, trailers.as_mut()) {
                    let _ = unit.await;
                    return closed_whole(h, block);
                }
                let running = Running(busbar_kernel::detached::spawn_detached(unit));
                return stated(h, Body::new(ReplyBody(body, Some(running), trailers)));
            }
            Ok(None) => unit.await,
            Err(rendered) => match head.try_recv() {
                Ok(h) if matches!(whole, WholeReplies::Collect) && whole_answer(&h.1) => {
                    let mut body = body;
                    let mut whole = Whole::default();
                    while let Ok(bytes) = body.try_recv() {
                        whole.push(bytes);
                    }
                    return stated(unlengthed(h), Body::from(whole.into_bytes()));
                }
                Ok(h) => {
                    let h = if whole_answer(&h.1) { unlengthed(h) } else { h };
                    if let Some(block) = closed_before_body(&body, trailers.as_mut()) {
                        return closed_whole(h, block);
                    }
                    return stated(h, Body::new(ReplyBody(body, None, trailers)));
                }
                Err(_) => rendered,
            },
        };
        unrendered(rendered)
    }
}

type UnitCaller = (
    PrincipalId,
    Option<Arc<busbar_contract::records::VirtualKey>>,
    Option<busbar_contract::redacted::Secret<Vec<u8>>>,
    Option<Vec<u8>>,
);

fn closed_before_body(
    body: &mpsc::Receiver<Bytes>,
    trailers: Option<&mut oneshot::Receiver<HeaderMap>>,
) -> Option<HeaderMap> {
    if !body.is_empty() {
        return None;
    }
    trailers?.try_recv().ok()
}

fn closed_whole(h: Head, block: HeaderMap) -> Response {
    let mut response = stated(h, Body::empty());
    response.headers_mut().remove(axum::http::header::TRAILER);
    response.headers_mut().extend(block);
    response
}

fn whole_answer(fields: &HeadFields) -> bool {
    let named = |field: &[u8]| {
        fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(field))
            .map(|(_, value)| String::from_utf8_lossy(value))
    };
    named(b"content-length").is_some()
        && !named(b"content-type").is_some_and(|v| streamed_media(&v))
}

fn declared_stream_media() -> impl Iterator<Item = &'static str> {
    busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .flat_map(|decl| {
            busbar_kernel::plane_driver::door::streaming_content_types(decl)
                .iter()
                .copied()
        })
}

fn streamed_media(content_type: &str) -> bool {
    std::iter::once(busbar_contract::protocol::TEXT_EVENT_STREAM)
        .chain(declared_stream_media())
        .any(|media| {
            content_type
                .get(..media.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(media))
        })
}

fn unlengthed((status, mut fields): Head) -> Head {
    fields.retain(|(name, _)| !name.eq_ignore_ascii_case(b"content-length"));
    (status, fields)
}

async fn collect(mut body: mpsc::Receiver<Bytes>, mut unit: DrivenUnit) -> Bytes {
    let mut whole = Whole::default();
    loop {
        tokio::select! {
            biased;
            piece = body.recv() => match piece {
                Some(bytes) => whole.push(bytes),
                None => {
                    let _ = unit.await;
                    break;
                }
            },
            _ = &mut unit => {
                while let Ok(bytes) = body.try_recv() {
                    whole.push(bytes);
                }
                break;
            }
        }
    }
    whole.into_bytes()
}

/// A whole answer's pieces, joined: a lone piece is kept as written, never copied.
#[derive(Default)]
struct Whole {
    one: Option<Bytes>,
    many: Vec<u8>,
}

impl Whole {
    fn push(&mut self, piece: Bytes) {
        match self.one.take() {
            None if self.many.is_empty() => self.one = Some(piece),
            first => {
                if let Some(first) = first {
                    self.many.extend_from_slice(&first);
                }
                self.many.extend_from_slice(&piece);
            }
        }
    }

    fn into_bytes(self) -> Bytes {
        self.one.unwrap_or_else(|| Bytes::from(self.many))
    }
}

pub type DrivenUnit = std::pin::Pin<Box<dyn std::future::Future<Output = Option<Rendered>> + Send>>;

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

struct Running(tokio::task::JoinHandle<Option<Rendered>>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ReplyBody(
    mpsc::Receiver<Bytes>,
    Option<Running>,
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
        match this.0.poll_recv(cx) {
            std::task::Poll::Ready(Some(bytes)) => {
                std::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes))))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(None) => {
                if let Some(running) = &mut this.1 {
                    match std::future::Future::poll(std::pin::Pin::new(&mut running.0), cx) {
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                        std::task::Poll::Ready(Err(e)) if e.is_panic() => {
                            std::panic::resume_unwind(e.into_panic())
                        }
                        std::task::Poll::Ready(_) => this.1 = None,
                    }
                }
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

fn framed_by(
    carrier: &str,
    framer_for: impl Fn(&str) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>>,
) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>> {
    if lines::carrier() == Some(carrier) {
        return None;
    }
    serve_framed::stream_framer(carrier, framer_for)
}

#[path = "serve_lines.rs"]
pub mod lines;

#[path = "serve_framed.rs"]
mod serve_framed;

#[path = "serve_datagram.rs"]
pub mod serve_datagram;

#[cfg(test)]
#[path = "tests/serve.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/serve_planes.rs"]
pub(crate) mod planes_tests;

#[cfg(all(test, linked_section_pools))]
#[path = "tests/serve_tests.rs"]
mod door_tests;

#[cfg(all(test, linked_section_pools))]
#[path = "tests/door_rig.rs"]
pub(crate) mod door_rig;

#[cfg(all(test, linked_section_pools))]
include!(concat!(env!("OUT_DIR"), "/door_cells.rs"));

#[cfg(test)]
#[path = "tests/serve_money.rs"]
mod money_tests;

#[cfg(all(test, linked_driver_proofs, linked_section_pools))]
#[path = "tests/serve_hook_seats.rs"]
pub(crate) mod hook_seat_tests;

#[cfg(all(test, linked_section_pools))]
#[path = "tests/serve_door_far.rs"]
mod door_far_tests;

#[cfg(all(test, linked_section_pools))]
#[path = "tests/serve_framed.rs"]
mod framed_tests;

#[cfg(all(test, linked_section_pools, linked_axis_plane_door))]
#[path = "tests/secret_source.rs"]
mod secret_source_tests;

#[cfg(all(test, linked_section_pools, linked_axis_plane_door))]
#[path = "tests/member_tls.rs"]
mod member_tls_tests;

#[cfg(all(test, linked_section_pools, linked_axis_plane_door))]
#[path = "tests/member_tls_negative.rs"]
mod member_tls_negative_tests;

#[cfg(test)]
#[path = "tests/journal_live_retry.rs"]
mod journal_live_retry_tests;

#[cfg(test)]
#[path = "tests/catalog_scope_provenance.rs"]
mod catalog_scope_provenance_tests;
