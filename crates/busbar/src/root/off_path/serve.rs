// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door planes' composition: what `serve` builds once per configuration, per published
//! generation or per process lifecycle (its planes, appliers, listener plan and mounts, its boot-time
//! workers and the ticket custody's sweep), never per request. The request path only reads what this
//! built; `serve` re-exports it under its old names.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome as AbiOutcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut};
use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};
use busbar_contract::caps::{OpClassId, ReasonCode};
use busbar_contract::plane_calls::PlaneCalls;
use busbar_contract::yaml::{MappingExt, ValueExt};
use busbar_kernel::host_services::KernelServices;
use busbar_kernel::plane_driver::serve::{ServeRoute, ServeTable, ServeTables};
use busbar_kernel::plane_driver::{
    refusal_status, BufferCaps, DriverConfig, MoneySeam, PlaneDriver, PlaneMoney,
};

use crate::root::boot::DoorPlane;
use crate::root::door_steps::{door_facts, DoorFacts, DoorPools};
use crate::root::loader::dispatch::kinds::plane::OwnedSnapshot;
use crate::root::loader::dispatch::plane_calls::PlaneInstance;

use crate::root::loader::dispatch::{in_head, out_head, Dispatcher, Frame};
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_contract::abi::plane::{CLAIM_EXACT, CLAIM_PATTERN};
use busbar_contract::caps::PrincipalId;
use busbar_kernel::observability::arrival::EntrySpans;
use busbar_kernel::plane_driver::Arrival;
use busbar_kernel::plane_routes::{
    PlaneRefusalSpec, PlaneReqCtx, PlaneRouteFuture, PlaneRouteSpec,
};

use crate::root::serve::*;

/// The model catalog, in the map type the configuration (`RootCfg::models`) holds it as.
pub(crate) type ModelCatalog = std::collections::HashMap<String, busbar_contract::config::ModelCfg>;

pub(crate) struct ApplyReach {
    pub(crate) providers: BTreeMap<String, crate::root::door_steps::ProviderRoute>,
    pub(crate) auths: Arc<crate::root::door_steps::OutboundAuths>,
    pub(crate) conns: Arc<dyn busbar_contract::conn::PollConns>,
    pub(crate) journal: Arc<dyn busbar_kernel_egress::ports::Journal>,
    pub(crate) stream_ceiling_secs: u64,

    pub(crate) catalog: Option<ModelCatalog>,
    pub(crate) upgrades: Vec<&'static str>,
}

/// The target of the first inbound need each carrier names: what names the carrier's listener
/// setting (`<section>.<target>.listen`) when a media offer on it is refused.
pub(crate) fn listen_targets(
    f: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
) -> foldhash::HashMap<&'static str, &'static str> {
    use busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND;
    let mut targets = foldhash::HashMap::default();
    for (((direction, _), target), transport) in f
        .need_auths
        .iter()
        .zip(&f.need_targets)
        .zip(&f.need_transports)
    {
        if *direction == DIRECTION_INBOUND && !target.is_empty() {
            targets.entry(*transport).or_insert(*target);
        }
    }
    targets
}

#[must_use]
pub(crate) fn applied_section(
    app: &busbar_kernel::state::App,
    plane: &str,
    section_key: &str,
    now: &DoorLive,
) -> busbar_contract::yaml::Value {
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
pub(crate) struct DoorAppliers(pub(crate) Vec<Arc<DoorApply>>);

impl DoorAppliers {
    pub(crate) async fn apply(&self, app: &busbar_kernel::state::App) {
        for plane in &self.0 {
            plane.apply(app).await;
        }
    }

    pub(crate) fn refresh_models(
        &self,
        sections: &BTreeMap<&'static str, busbar_contract::yaml::Value>,
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
            let owned = match owned_sections(facts, sections) {
                Ok(owned) => owned,
                Err(e) => {
                    tracing::error!(plane = name, error = %e, "door plane's new configuration is not JSON; it keeps serving the previous one");
                    continue;
                }
            };
            if let Err(e) = crate::root::loader::dispatch::kinds::plane::refresh_door_on(
                &p.plugin,
                &p.dispatcher,
                &settings,
                &owned,
                next,
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
                    if !live.observations.is_empty() && !p.observations_supported {
                        tracing::error!(
                            plane = name,
                            "usage observations require an atomic durable store"
                        );
                        continue;
                    }
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

impl Served {
    /// One process-owned scanner. Kept and joined by main before storage retirement.
    pub(crate) fn spawn_work_recovery(
        &self,
        app: Arc<busbar_kernel::state::AppHandle>,
        admission: Arc<busbar_kernel::limits::process_admission::ProcessAdmission>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let routes = self.nests.clone();
        let kernels: Vec<_> = self.planes.iter().map(|p| p.kernel.clone()).collect();
        struct Ready(
            Vec<Arc<KernelServices>>,
            Option<Arc<crate::root::min3_boot::Booted>>,
        );
        impl Drop for Ready {
            fn drop(&mut self) {
                for kernel in &self.0 {
                    kernel.set_recovery_scheduler_ready(false);
                }
                if let Some(native) = &self.1 {
                    crate::root::min3_boot::set_recovery_ready(native, false);
                }
            }
        }
        let ready = Ready(kernels, self.native.clone());
        if routes.is_some() {
            for kernel in &ready.0 {
                kernel.set_recovery_scheduler_ready(true);
            }
        }
        // The MIN-3 plane seats' durable WORK is recovered by this same scheduler (IF §12.24 step 3).
        let native = self.native.clone();
        let ports = native
            .as_ref()
            .is_some_and(|booted| !booted.seats.is_empty());
        if let Some(native) = &native {
            crate::root::min3_boot::set_recovery_ready(native, ports);
        }
        tokio::spawn(async move {
            let _ready = ready;
            if routes.is_none() && !ports {
                return;
            }
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.recv() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                }
                let live: Vec<_> = routes
                    .as_ref()
                    .map(|routes| {
                        routes
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .iter()
                            .filter_map(std::sync::Weak::upgrade)
                            .collect()
                    })
                    .unwrap_or_default();
                let cycle = async {
                    for routes in live {
                        routes.recover_work(app.load(), &admission).await;
                    }
                    if let Some(native) = &native {
                        crate::root::min3_boot::recover_ports(native, app.load()).await;
                    }
                };
                tokio::select! {
                    biased;
                    _ = shutdown.recv() => break,
                    _ = cycle => {}
                }
            }
        })
    }

    #[must_use]
    pub(crate) fn appliers(&self) -> DoorAppliers {
        let tail = DoorAppliers(self.planes.iter().map(|p| Arc::clone(&p.live)).collect());
        tail
    }

    #[must_use]
    pub(crate) fn need_trust(&self) -> Vec<&'static str> {
        let tail = self
            .planes
            .iter()
            .flat_map(|p| p.live.served_facts.need_trust.iter().copied())
            .collect();
        tail
    }

    #[must_use]
    pub(crate) fn member_tls_sections(&self) -> Vec<&'static str> {
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
    pub(crate) fn unopened(&self, doors: &[(String, DoorPlane)]) -> Vec<&'static str> {
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
    pub(crate) fn spawn_ticks(&self) {
        for p in &self.planes {
            let driver = Arc::clone(&p.driver);
            tokio::spawn(async move { driver.ticks().await });
            let driver = Arc::clone(&p.driver);
            tokio::spawn(async move { driver.drives().await });
        }

        // The post holds the Node weakly; a Node already gone has no lease to tick.
        if let Some(node) = self.post.as_ref().and_then(|post| post.node()) {
            tokio::spawn(LeaseTick { node }.ticks());
        }
    }
}

pub(crate) struct LeaseTick {
    pub(crate) node: Arc<crate::root::plane_node::Node>,
}

impl LeaseTick {
    pub(crate) async fn tick(&self) -> Result<(), String> {
        // Native node-lease renewal belongs to the book's root-owned lifecycle.
        // This worker only retries original journal custody asynchronously.
        self.node.retry_held_journal().await
    }

    pub(crate) async fn ticks(self) {
        let every = busbar_kernel::host_records::FLUSH_INTERVAL;
        let mut at = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        at.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let this = Arc::new(self);
        let shutdown = busbar_kernel::detached::worker_shutdown();

        let mut sweep: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> =
            None;
        type JournalFlush =
            std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>;
        let mut flushing: Option<JournalFlush> = None;
        // The existing native audit queue owns uncertain refusal/export originals. Keep its
        // driver independent of the journal so an isolated lost ACK needs no later request.
        let mut auditing: Option<JournalFlush> = None;
        // The store settle pass is its own future: a stalled store never blocks the flush.
        let mut settling: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> =
            None;
        // Native DATA audit r2: the retained process pulse drives installed native entries,
        // at most the adopted 64 candidates per pass, resuming from the retained cursor.
        type NativeDrive =
            std::pin::Pin<Box<dyn std::future::Future<Output = (usize, Option<u64>)> + Send>>;
        let mut native_cursor: Option<u64> = None;
        let mut driving: Option<NativeDrive> = None;
        loop {
            tokio::select! {
                biased;
                () = busbar_kernel::detached::shutdown_fired(shutdown.clone()) => {
                    this.node.ticket_custody.shutdown();
                    return;
                }
                _ = at.tick() => {
                    if flushing.is_none() {
                        let tick = Arc::clone(&this);
                        flushing = Some(Box::pin(async move { tick.tick().await }));
                    }
                    if auditing.is_none() && busbar_kernel::audit::auditlog::has_unsettled_audit() {
                        auditing = Some(Box::pin(async {
                            busbar_kernel::audit::auditlog::flush_pending()
                                .await
                                .map_err(|error| error.to_string())
                        }));
                    }
                    if sweep.is_none() {
                        let custody = Arc::clone(&this.node.ticket_custody);
                        sweep = Some(Box::pin(async move { custody.sweep().await }));
                    }
                    if settling.is_none() {
                        let node = Arc::clone(&this.node);
                        settling = Some(Box::pin(async move { node.settle_store().await }));
                    }
                    if driving.is_none() && this.node.native_pending() != 0 {
                        let node = Arc::clone(&this.node);
                        let mut cursor = native_cursor;
                        driving = Some(Box::pin(async move {
                            let retired = node.drive_native(&mut cursor).await;
                            (retired, cursor)
                        }));
                    }
                }
                // r2's journal-progress trigger: a confirmed audit run can advance staged native
                // entries before the next regular tick.
                () = crate::root::durability::records_pulse().notified(),
                    if driving.is_none() && this.node.native_pending() != 0 =>
                {
                    let node = Arc::clone(&this.node);
                    let mut cursor = native_cursor;
                    driving = Some(Box::pin(async move {
                        let retired = node.drive_native(&mut cursor).await;
                        (retired, cursor)
                    }));
                }
                result = async {
                    match flushing.as_mut() {
                        Some(flushing) => flushing.await,
                        None => std::future::pending().await,
                    }
                } => {
                    flushing = None;
                    if let Err(error) = result { tracing::warn!(reason = error, "native journal custody is still pending"); }
                }
                result = async {
                    match auditing.as_mut() {
                        Some(auditing) => auditing.await,
                        None => std::future::pending().await,
                    }
                } => {
                    auditing = None;
                    if let Err(error) = result { tracing::warn!(reason = error, "native audit originals are still pending"); }
                }
                () = async {
                    match sweep.as_mut() {
                        Some(sweep) => sweep.await,
                        None => std::future::pending().await,
                    }
                } => { sweep = None; }
                () = async {
                    match settling.as_mut() {
                        Some(settling) => settling.await,
                        None => std::future::pending().await,
                    }
                } => { settling = None; }
                (_, cursor) = async {
                    match driving.as_mut() {
                        Some(driving) => driving.await,
                        None => std::future::pending().await,
                    }
                } => {
                    driving = None;
                    native_cursor = cursor;
                }
            }
        }
    }
}

pub(crate) async fn compose_served_checked(
    native: Option<Arc<crate::root::min3_boot::Booted>>,
    gov: Option<Arc<busbar_kernel::governance::GovState>>,
    doors: &[(String, DoorPlane)],
    dispatcher: &Arc<Dispatcher>,
    late: &Services,
    sections: &BTreeMap<&'static str, busbar_contract::yaml::Value>,
    accepted: &busbar_kernel::config::min3::InsecureTransportMap,
    public_url: Option<&str>,
    reach: &crate::root::door_steps::DoorReach<'_>,
    tables: &ServeTables,
    check: &dyn Fn(&Served) -> Result<Vec<crate::root::loader::boot::InboundBind>, String>,
) -> Result<Served, String> {
    let Some(gov) = gov else {
        if !doors.is_empty() {
            tracing::warn!("door planes stay unopened: no governance book to settle on");
        }
        let served = Served {
            ports: native
                .as_ref()
                .map(|native| native.seats.clone())
                .unwrap_or_default(),
            native,
            ..Served::default()
        };
        check(&served)?;
        return Ok(served);
    };
    let post = Arc::new(crate::root::plane_node::NodeEndPost::new(
        crate::root::plane_node::node(),
    ));
    let journal = Arc::clone(&post) as Arc<dyn busbar_kernel::plane_driver::HookJournal>;
    let site = Arc::clone(&post);
    let caller_migration = gov.clone();
    let port_billing = busbar_kernel::plane_driver::port_billing::PortBilling::new(
        Arc::new(PlaneMoney::new(
            Arc::clone(&gov),
            Arc::clone(&post) as Arc<dyn busbar_kernel::plane_driver::EndPost>,
        )),
        Arc::clone(&gov),
        crate::root::plane_node::node().kernel_and_keys().1,
        Arc::new(busbar_kernel::plane_driver::CoreAudit),
    )
    .with_journal(Arc::clone(&post) as Arc<dyn busbar_kernel::plane_driver::HookJournal>);
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
        accepted,
        public_url,
        &money,
        Some(&egress),
        Some(&journal),
        tables,
    )
    .await?;
    for plane in &served.planes {
        plane
            .driver
            .migrate_caller_references(&caller_migration)
            .await?;
    }
    served.ports = native
        .as_ref()
        .map(|native| native.seats.clone())
        .unwrap_or_default();
    served.native = native;
    served.post = Some(post);
    served.billing = Some(port_billing);
    let binds = check(&served)?;

    if !binds.is_empty() {
        served.claim_doors = serve_datagram::ClaimDoors::bind(&binds, |t| {
            crate::root::connector::the().framer_for(t)
        })?;
    }
    Ok(served)
}

#[cfg(test)]
pub(crate) fn datagram_binds(
    doors: &[(String, DoorPlane)],
    sections: &BTreeMap<&'static str, busbar_contract::yaml::Value>,
) -> Result<Vec<crate::root::loader::boot::InboundBind>, String> {
    let mut binds = Vec::new();
    for (instance, plugin) in doors {
        binds.extend(need_binds(
            instance,
            plugin.served().section,
            plugin.declared_needs(),
            sections,
        )?);
    }
    Ok(binds)
}

#[cfg(test)]
pub(crate) fn need_binds(
    instance: &str,
    section_name: &str,
    needs: &[busbar_contract::abi::mechanism::rendering::ReadNeed],
    sections: &BTreeMap<&'static str, busbar_contract::yaml::Value>,
) -> Result<Vec<crate::root::loader::boot::InboundBind>, String> {
    let Some(section) = sections.get(section_name) else {
        return Ok(Vec::new());
    };
    let settings: busbar_contract::plugin_settings::Settings =
        busbar_contract::yaml::from_value(section.clone())
            .map_err(|_| format!("{section_name}: settings must be an object"))?;
    let claims =
        busbar_contract::conn::inbound::admit(&busbar_kernel::seal::acquire(), &settings, needs)
            .map_err(|why| format!("{section_name}.{why}"))?;
    let mut binds = Vec::new();
    for claim in claims {
        let at = format!("{section_name}.{}", claim.path);
        let Some(binding) = claim.binding else {
            if matches!(claim.path.as_str(), "listen" | "ingress") {
                continue;
            }
            return Err(format!("{at}: not set; an inbound listener needs `listen`"));
        };
        binds.push(crate::root::loader::boot::InboundBind {
            owner: crate::root::loader::boot::BindOwner::Need {
                instance: instance.to_string(),
                kind: busbar_contract::abi::mechanism::KindCode::Plane,
                need: claim.need,
            },
            transport: needs[claim.need as usize].transport.clone(),
            at,
            listen: binding.listen,
            tls: binding.tls,
            max_conns: binding.max_conns,
        });
    }
    Ok(binds)
}

#[must_use]
pub(crate) fn with_pools(
    mut sections: BTreeMap<&'static str, busbar_contract::yaml::Value>,
    pools: &[(
        &'static str,
        BTreeMap<String, busbar_kernel::config::pools::CandidatePoolCfg>,
    )],
) -> BTreeMap<&'static str, busbar_contract::yaml::Value> {
    for (key, stated) in pools {
        if let Some(section) = sections.get_mut(key) {
            pools_into(section, stated);
        }
    }
    sections
}

pub(crate) type DoorPoolsByKey = Vec<(
    &'static str,
    BTreeMap<String, busbar_kernel::config::pools::CandidatePoolCfg>,
)>;

#[must_use]
pub(crate) fn door_pools(
    plane_pools: &BTreeMap<
        &'static str,
        BTreeMap<String, busbar_kernel::config::pools::CandidatePoolCfg>,
    >,
) -> DoorPoolsByKey {
    let tail = plane_pools
        .iter()
        .map(|(section, pools)| (*section, pools.clone()))
        .collect();
    tail
}

#[must_use]
pub(crate) fn installed_door_pools(app: &busbar_kernel::state::App) -> DoorPoolsByKey {
    let tail = busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .filter_map(|decl| {
            app.plane_pools(decl.key)
                .map(|pools| (decl.config_section, pools.clone()))
        })
        .collect();
    tail
}

pub(crate) fn section_with_pools(
    key: &str,
    written: &busbar_contract::yaml::Value,
    pools: &[(
        &'static str,
        BTreeMap<String, busbar_kernel::config::pools::CandidatePoolCfg>,
    )],
) -> busbar_contract::yaml::Value {
    let mut section = written.clone();
    for (owner, stated) in pools {
        if *owner == key {
            pools_into(&mut section, stated);
        }
    }
    section
}

pub(crate) fn handed_settings(
    path: &[&str],
    section: &busbar_contract::yaml::Value,
) -> Result<Vec<u8>, String> {
    let mut section = plane_settings(section);
    if let Some(map) = section.as_mapping_mut() {
        map.remove_key(busbar_contract::section::RESERVED_WORK_KEY);
    }
    let tail = busbar_kernel::config::filled::plane_bound_bytes(path, &section)
        .map_err(|e| format!("its section: {e}"));
    tail
}

pub(crate) fn settings_path(
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
) -> &[&'static str] {
    if handed_keyed(facts) {
        &[]
    } else {
        std::slice::from_ref(&facts.section)
    }
}

pub(crate) fn pools_into(
    section: &mut busbar_contract::yaml::Value,
    stated: &BTreeMap<String, busbar_kernel::config::pools::CandidatePoolCfg>,
) {
    use busbar_contract::section::{
        POOL_MEMBERS_KEY, POOL_MEMBER_GRANTED_KEY, POOL_MEMBER_NAME_KEY, POOL_MEMBER_TIER_KEY,
        POOL_REPEATABLE_KEY, RESERVED_POOLS_KEY,
    };
    if stated.is_empty() {
        return;
    }
    let busbar_contract::yaml::Value::Map(section) = section else {
        return;
    };
    let mut map = busbar_contract::yaml::Pairs::new();
    for (name, pool) in stated {
        let mut entry = busbar_contract::yaml::Pairs::new();
        entry.insert_key(
            POOL_MEMBERS_KEY,
            busbar_contract::yaml::Value::Array(
                pool.members
                    .iter()
                    .zip(0u64..)
                    .map(|(m, tier)| {
                        let mut member = busbar_contract::yaml::Pairs::new();
                        member.insert_key(POOL_MEMBER_NAME_KEY, m.as_str().into());
                        member.insert_key(POOL_MEMBER_TIER_KEY, tier.into());
                        busbar_contract::yaml::Value::Map(member)
                    })
                    .collect(),
            ),
        );
        entry.insert_key(
            POOL_REPEATABLE_KEY,
            busbar_contract::yaml::Value::Array(
                pool.repeatable.iter().map(|m| m.as_str().into()).collect(),
            ),
        );
        entry.insert_key(
            POOL_MEMBER_GRANTED_KEY,
            busbar_contract::yaml::Value::Bool(true),
        );

        if let Some(block) = pool
            .breaker
            .as_ref()
            .and_then(|b| busbar_contract::yaml::to_value(b).ok())
        {
            entry.insert_key(crate::root::door_steps::POOL_BREAKER_KEY, block);
        }
        map.insert_key(name.as_str(), busbar_contract::yaml::Value::Map(entry));
    }
    section.insert_key(RESERVED_POOLS_KEY, busbar_contract::yaml::Value::Map(map));
}

#[must_use]
pub(crate) fn plane_settings(
    section: &busbar_contract::yaml::Value,
) -> busbar_contract::yaml::Value {
    use busbar_contract::section::{POOL_MEMBERS_KEY, POOL_MEMBER_NAME_KEY, RESERVED_POOLS_KEY};
    let mut section = section.clone();
    if let Some(map) = section.as_mapping_mut() {
        map.remove_key(busbar_contract::section::USAGE_OBSERVATIONS_KEY);
    }
    let pools = section
        .as_mapping_mut()
        .and_then(|m| m.get_key_mut(RESERVED_POOLS_KEY))
        .and_then(busbar_contract::yaml::Value::as_mapping_mut);
    for (_, pool) in pools.into_iter().flat_map(|p| p.iter_mut()) {
        if let Some(pool) = pool.as_mapping_mut() {
            pool.remove_key(crate::root::door_steps::POOL_BREAKER_KEY);
        }
        let members = pool
            .as_mapping_mut()
            .and_then(|p| p.get_key_mut(POOL_MEMBERS_KEY))
            .and_then(busbar_contract::yaml::Value::as_sequence_mut);
        for member in members.into_iter().flat_map(|m| m.iter_mut()) {
            let name = member
                .get(POOL_MEMBER_NAME_KEY)
                .and_then(busbar_contract::yaml::Value::as_str)
                .map(str::to_owned);
            if let Some(name) = name {
                *member = busbar_contract::yaml::Value::Text(name);
            }
        }
    }
    section
}

pub(crate) struct DoorEgress<'a> {
    pub(crate) reach: &'a crate::root::door_steps::DoorReach<'a>,

    pub(crate) journal: Arc<dyn busbar_kernel_egress::ports::Journal>,
}

pub(crate) async fn compose_planes(
    doors: &[(String, DoorPlane)],
    dispatcher: &Arc<Dispatcher>,
    late: &Services,
    sections: &BTreeMap<&'static str, busbar_contract::yaml::Value>,
    accepted: &busbar_kernel::config::min3::InsecureTransportMap,
    public_url: Option<&str>,
    money: &dyn Fn() -> Arc<PlaneMoney>,
    egress: Option<&DoorEgress<'_>>,
    journal: Option<&Arc<dyn busbar_kernel::plane_driver::HookJournal>>,
    tables: &ServeTables,
) -> Result<Served, String> {
    let scope = busbar_contract::config_time::ConfigScope::config_time();

    let clock: busbar_ports::clock::HostClock =
        busbar_ports::clock::HostClock::system(crate::root::egress_ports::tokio_sleep);
    compose_planes_over(
        &crate::LINKED,
        doors,
        dispatcher,
        late,
        sections,
        accepted,
        public_url,
        money,
        egress,
        journal,
        &clock,
        &scope,
        tables,
    )
    .await
}

pub(crate) async fn compose_planes_over(
    linked: &crate::root::linked::Linked,
    doors: &[(String, DoorPlane)],
    dispatcher: &Arc<Dispatcher>,
    late: &Services,
    sections: &BTreeMap<&'static str, busbar_contract::yaml::Value>,
    accepted: &busbar_kernel::config::min3::InsecureTransportMap,
    public_url: Option<&str>,
    money: &dyn Fn() -> Arc<PlaneMoney>,
    egress: Option<&DoorEgress<'_>>,
    journal: Option<&Arc<dyn busbar_kernel::plane_driver::HookJournal>>,
    clock: &busbar_ports::clock::HostClock,
    scope: &busbar_contract::config_time::ConfigScope,
    tables: &ServeTables,
) -> Result<Served, String> {
    let mut served = Served {
        tables: tables.clone(),
        ..Served::default()
    };
    let Some(kernel) = late.kernel() else {
        if doors.is_empty() {
            return Ok(served);
        }
        return Err("the kernel's host services are not composed".into());
    };
    let first_start = match kernel.native_first_start() {
        Some(proof) if !proof.published().await => Some(proof),
        _ => None,
    };
    let mut staged_tables = Vec::new();
    if let Some(proof) = &first_start {
        use busbar_contract::crypto::Sha256;
        let mut plan = Vec::new();
        for (instance, plugin) in doors {
            if !plugin.declared().conditional_records {
                continue;
            }
            let facts = plugin.served();
            let empty = busbar_contract::yaml::Value::Map(busbar_contract::yaml::Pairs::new());
            let section = match sections.get(facts.section) {
                Some(section) => section,
                None if facts.owns.iter().any(|name| sections.contains_key(name)) => &empty,
                None => continue,
            };
            let caller = plugin
                .service_caller()
                .ok_or("initial plane caller is unbound")?;
            let settings = settings_of(&facts, section, sections);
            let walked = walked_section(&facts, section, sections);
            let owned = owned_sections(&facts, sections)?;
            let dialects = egress
                .map(|e| crate::root::door_steps::dialect_facts(&walked, e.reach.providers))
                .unwrap_or_default();
            let handed = busbar_contract::secure::SecureVec::from(handed_settings(
                settings_path(&facts),
                &settings,
            )?);
            let owned = busbar_contract::secure::SecureVec::from(owned);
            let mut hash = Sha256::new();
            hash.update(b"busbar.initial-record-binding/1\0");
            for bytes in [
                instance.as_bytes(),
                caller.namespace().as_bytes(),
                plugin.name().as_bytes(),
                public_url.unwrap_or_default().as_bytes(),
                plugin.statement_digest().as_slice(),
                handed.as_slice(),
                owned.as_slice(),
            ] {
                hash.update(&(bytes.len() as u64).to_be_bytes());
                hash.update(bytes);
            }
            hash.update(&(dialects.len() as u64).to_be_bytes());
            for dialect in dialects {
                for bytes in [
                    dialect.name.as_bytes(),
                    dialect.protocol.as_bytes(),
                    dialect.error_map.as_deref().unwrap_or_default(),
                ] {
                    hash.update(&(bytes.len() as u64).to_be_bytes());
                    hash.update(bytes);
                }
                hash.update(&[u8::from(dialect.error_map.is_some())]);
            }
            plan.push(busbar_kernel::persistence::first_start::Binding {
                instance: instance.clone(),
                digest: hash.finish(),
            });
        }
        plan.sort_by(|a, b| a.instance.cmp(&b.instance));
        confirm_first_start(|| proof.freeze(plan.clone())).await?;
    }
    for (instance, plugin) in doors {
        let served_facts = plugin.served();

        let empty = busbar_contract::yaml::Value::Map(busbar_contract::yaml::Pairs::new());
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

        let owned = owned_sections(&served_facts, sections)?;

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
        let caller = plugin
            .service_caller()
            .ok_or_else(|| format!("{instance}: plane has no bound service caller"))?;
        kernel
            .bind_record_bootstrap_caller(&caller)
            .map_err(|why| format!("{instance}: {why}"))?;
        let driver = PlaneDriver::new(
            Arc::clone(&calls) as Arc<dyn PlaneCalls>,
            config,
            Arc::clone(&plane_money) as Arc<dyn MoneySeam>,
            Arc::clone(&kernel),
            (served_facts.section, section),
        )
        .await
        .map_err(|e| format!("{instance}: {e}"))?
        .with_records(Arc::clone(&kernel), caller.clone());

        if plugin.declared().conditional_records {
            if plugin.has_ready() {
                kernel
                    .bind_native_record_bootstrap(&caller)
                    .await
                    .map_err(str::to_string)?;
                let ready_plugin = plugin.clone();
                let ready_dispatcher = Arc::clone(dispatcher);
                tokio::task::spawn_blocking(move || {
                    ready_plugin.ready(
                        &ready_dispatcher,
                        crate::root::loader::dispatch::ready::READY_DEADLINE,
                    )
                })
                .await
                .map_err(|error| format!("{instance}: READY worker: {error}"))??;
            }
            if let Some(proof) = &first_start {
                confirm_first_start(|| proof.complete(instance)).await?;
                kernel
                    .revoke_native_record_bootstrap(&caller)
                    .map_err(str::to_string)?;
            }
        }

        let driver = match journal {
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

        staged_tables.push(ServeTable {
            instance: instance.clone(),
            audit_kind: served_facts.audit_kind.to_string(),
            calls,
            caps: BufferCaps::default(),
            routes,
            records: Some((Arc::clone(&kernel), caller)),
        });
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
        if !live.observations.is_empty() && !plane_money.observations_supported() {
            return Err(format!(
                "{instance}: usage observations require an atomic durable store"
            ));
        }
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
            instance: Arc::from(instance.as_str()),
            observations_supported: plane_money.observations_supported(),
            listen_targets: listen_targets(&served_facts),
            plugin: plugin.clone(),
            dispatcher: Arc::clone(dispatcher),
            served_facts: served_facts.clone(),
            facts: facts.clone(),
            reach,
            live: std::sync::RwLock::new(Arc::new(live)),
            driver: Arc::clone(&driver),
            probe_schedule,
            scope_kinds: declared.scope_kinds.clone(),
            clock: clock.clone(),
            units: Arc::clone(kernel.units()),
        });
        served.planes.push(ServedPlane {
            instance: instance.clone(),
            driver,
            snapshot,
            #[cfg(test)]
            audit_kind: served_facts.audit_kind,
            facts,
            money: plane_money,
            live,
            kernel: Arc::clone(&kernel),
            dialects: served_facts.dialects.clone(),
            // #297 model A: the instance's `InstanceSpec.limits.accept`, the same value its native seat
            // is opened with: its own section's `insecure_transport` (TRANSPORT-SECURITY-POLICY §4).
            accept: busbar_kernel::appbuild::limits_of(
                accepted,
                served_facts.section,
                served_facts.section,
            )
            .accept,
        });
    }
    served
        .tables
        .validate_batch(&staged_tables, &[])
        .map_err(|c| format!("admin route {:?} overlaps {}", c.route, c.with))?;
    if let Some(proof) = &first_start {
        confirm_first_start(|| proof.publish()).await?;
    }
    served
        .tables
        .publish_batch(staged_tables, &[])
        .map_err(|c| format!("admin route {:?} overlaps {}", c.route, c.with))?;
    Ok(served)
}

pub(crate) async fn confirm_first_start<F, T>(mut advance: F) -> Result<(), String>
where
    F: FnMut() -> T,
    T: std::future::Future<
        Output = Result<
            busbar_kernel::persistence::startup::Progress,
            busbar_kernel::persistence::startup::Error,
        >,
    >,
{
    use busbar_kernel::persistence::startup::Progress;
    loop {
        let progress = advance()
            .await
            .map_err(|error| format!("native first publication refused: {error:?}"))?;
        match progress {
            Progress::Advanced => return Ok(()),
            Progress::Pending => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
            _ => return Err("native first publication requires reconciliation".into()),
        }
    }
}

pub(crate) const SESSION_KEY: &str = "session";
pub(crate) const MODEL_KEY: &str = "model";

pub(crate) fn fold_catalog_routes(
    section: &busbar_contract::yaml::Value,
    catalog: &ModelCatalog,
) -> (busbar_contract::yaml::Value, Option<String>) {
    use busbar_contract::yaml::{Pairs, Value};
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
    let mut folded = Pairs::new();
    folded.insert_key("provider", entry.provider.clone().into());
    if let Some(upstream) = &entry.upstream_model {
        folded.insert_key("upstream_model", upstream.clone().into());
    }
    if let Some(ms) = entry.attempt_timeout_ms {
        folded.insert_key("attempt_timeout_ms", ms.into());
    }
    let mut models = Pairs::new();
    models.insert_key(model, Value::Map(folded));
    map.insert_key(models_key, Value::Map(models));
    (routes, Some(model.to_string()))
}

pub(crate) fn routes_of(
    section: &busbar_contract::yaml::Value,
    catalog: Option<&ModelCatalog>,
) -> (busbar_contract::yaml::Value, Option<String>) {
    catalog.map_or_else(
        || (section.clone(), None),
        |c| fold_catalog_routes(section, c),
    )
}

/// A route synthesized from the catalog and a matching declared secondary kind are host facts.
pub(crate) fn seal_secondary_scopes(
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

pub(crate) fn seal_live(
    instance: &str,
    plugin: &DoorPlane,
    served_facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    scope_kinds: &[&str],
    section: &busbar_contract::yaml::Value,
    egress: Option<&DoorEgress<'_>>,
    clock: &busbar_ports::clock::HostClock,
    generation: u64,
    bench_below_trip_threshold: Option<bool>,
    scope: &busbar_contract::config_time::ConfigScope,
    units: &Arc<busbar_kernel::host_units::UnitRecords>,
) -> Result<DoorLive, String> {
    let models_plane = served_facts.section == busbar_contract::section::RESERVED_POOLS_KEY;
    let mut facts = door_facts(
        busbar_kernel::plane_driver::dispatch::LaneQualifier::parse(if models_plane {
            ""
        } else {
            plugin.name()
        })
        .map_err(|e| format!("plane {}: {e}", plugin.name()))?,
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
    facts.route_cost.clone_from(&served_facts.route_cost);

    facts.stream_ceiling_secs = served_facts.stream_ceiling_secs;

    let dialects = served_facts
        .dialects
        .iter()
        .map(|d| (*d).to_string())
        .collect();
    facts.dialects = dialects;

    let metric_lanes = served_facts
        .metric_lanes
        .iter()
        .map(|w| (*w).to_string())
        .collect();
    facts.metric_lanes = metric_lanes;
    if let Some(egress) = egress {
        let translations = (
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
        facts.translations = translations;
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
                    clock.clone(),
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
                    clock.clone(),
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
    let observations =
        crate::root::off_path::serve_observations::parse(instance, section, &facts, &pools)?;
    Ok(DoorLive {
        observations,
        ticket_nonce: Arc::new(()),
        section: section.clone(),
        generation,
        pools,
        egress,
        facts,
        probes: None,
        shown,
    })
}

pub(crate) fn bind_fetches(
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

pub(crate) fn arm_probes(
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

/// The sections the plane owns, as the JSON object it is handed (no bytes when it owns none).
pub(crate) fn owned_sections(
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    sections: &BTreeMap<&'static str, busbar_contract::yaml::Value>,
) -> Result<Vec<u8>, String> {
    let mut owned = serde_json::Map::new();
    for name in &facts.owns {
        let Some(section) = sections.get(name) else {
            continue;
        };
        let value = serde_json::to_value(section)
            .map_err(|_| format!("{name}: owned section is not JSON"))?;
        let value = busbar_kernel::config::filled::plane_bound(&[name], value)
            .map_err(|error| format!("{name}: {error}"))?;
        owned.insert((*name).to_string(), value);
    }
    if owned.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = serde_json::to_vec(&owned).map_err(|e| format!("its owned sections: {e}"))?;
    Ok(bytes)
}

pub(crate) fn handed_keyed(
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
) -> bool {
    facts.section == busbar_contract::section::RESERVED_POOLS_KEY || !facts.consumed.is_empty()
}

pub(crate) fn settings_of(
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    section: &busbar_contract::yaml::Value,
    sections: &BTreeMap<&'static str, busbar_contract::yaml::Value>,
) -> busbar_contract::yaml::Value {
    if !handed_keyed(facts) {
        let mut settings = section.clone();
        if let Some(map) = settings.as_mapping_mut() {
            map.remove_key(busbar_contract::section::USAGE_OBSERVATIONS_KEY);
        }
        return settings;
    }
    let own = if facts.section == busbar_contract::section::RESERVED_POOLS_KEY {
        let mut own = section.clone();
        if let Some(map) = own.as_mapping_mut() {
            map.remove_key(busbar_contract::section::USAGE_OBSERVATIONS_KEY);
        }
        own
    } else {
        let mut own = plane_settings(section);
        if let Some(map) = own.as_mapping_mut() {
            map.remove_key(busbar_contract::section::RESERVED_WORK_KEY);
            map.remove_key(busbar_contract::section::USAGE_OBSERVATIONS_KEY);
        }
        own
    };
    let mut keyed = busbar_contract::yaml::Pairs::new();
    keyed.insert_key(facts.section, own);
    for name in &facts.consumed {
        if let Some(value) = sections.get(name) {
            keyed.insert_key(*name, value.clone());
        }
    }
    busbar_contract::yaml::Value::Map(keyed)
}

pub(crate) fn walked_section(
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    section: &busbar_contract::yaml::Value,
    sections: &BTreeMap<&'static str, busbar_contract::yaml::Value>,
) -> busbar_contract::yaml::Value {
    use busbar_contract::section::{RESERVED_MODELS_KEY, RESERVED_POOLS_KEY};
    let models = facts
        .consumed
        .contains(&RESERVED_MODELS_KEY)
        .then(|| sections.get(RESERVED_MODELS_KEY))
        .flatten();
    match models {
        Some(models) if facts.section == RESERVED_POOLS_KEY => {
            let mut uniform = busbar_contract::yaml::Pairs::new();
            uniform.insert_key(RESERVED_MODELS_KEY, models.clone());
            let mut pools = section.clone();
            if let Some(policy) = pools
                .as_mapping_mut()
                .and_then(|m| m.remove_key(busbar_contract::section::USAGE_OBSERVATIONS_KEY))
            {
                uniform.insert_key(busbar_contract::section::USAGE_OBSERVATIONS_KEY, policy);
            }
            uniform.insert_key(RESERVED_POOLS_KEY, pools);
            busbar_contract::yaml::Value::Map(uniform)
        }
        _ => section.clone(),
    }
}

pub(crate) fn open(
    plugin: &DoorPlane,
    path: &[&str],
    section: &busbar_contract::yaml::Value,
    public_url: Option<&str>,
    owned: &[u8],
    dialects: &[busbar_contract::plane_calls::DialectFacts],
) -> Result<OwnedSnapshot, String> {
    let settings = handed_settings(path, section)?;
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
    let (called, snapshot) = plugin.answer_open(&mut frame);
    if called.outcome != AbiOutcome::Ready {
        return Err(called.open_failure(plugin.name()));
    }
    snapshot.ok_or_else(|| "its snapshot did not pass the host's checks".to_string())
}

pub(crate) fn arrival_entries(served: &Served) -> Vec<Arc<EntrySpans>> {
    let tail = served
        .planes
        .iter()
        .map(|plane| {
            Arc::new(EntrySpans::of(plane.snapshot.claims.iter().map(|claim| {
                (
                    claim.verb.as_str(),
                    claim.target.as_str(),
                    claim.flags,
                    claim.arrival_span.as_str(),
                )
            })))
        })
        .collect();
    tail
}

/// Project only the candidate retained by this request. A current global handle is never
/// consulted, so a reload cannot substitute a different physical route token mid-request.
pub(crate) fn native_slot(
    app: &busbar_kernel::state::App,
    slot: &str,
) -> Option<Arc<crate::root::min3_physical::NativeSlot>> {
    app.config_projection
        .as_ref()?
        .downcast_ref::<crate::root::door_steps::DoorConfig>()?
        .native_slots
        .get(slot)
        .cloned()
}

/// Install a complete prepared map on an unpublished candidate; the caller publishes App
/// only after every slot has passed its actual transport/route/class checks.
pub(crate) fn install_native_slots(
    app: &mut busbar_kernel::state::App,
    slots: crate::root::min3_physical::NativeSlots,
) -> Result<(), String> {
    if slots.iter().any(|(name, slot)| name != slot.slot()) {
        return Err("native slot map key differs from its physical owner".into());
    }
    let mut config = app
        .config_projection
        .as_ref()
        .and_then(|value| value.downcast_ref::<crate::root::door_steps::DoorConfig>())
        .ok_or("native listener candidate has no root configuration projection")?
        .clone();
    config.native_slots = slots;
    app.config_projection = Some(Arc::new(config));
    Ok(())
}

/// A claim line's auth, built with the route table (once per generation): an open claim needs none, any
/// other the plane's data chain.
pub(crate) fn line_auth(flags: u32, data_chain: &[ChainAuth]) -> busbar_kernel::guest::LineAuth {
    if flags & busbar_contract::abi::plane::CLAIM_OPEN != 0 {
        busbar_kernel::guest::LineAuth::None
    } else {
        chain_auth(data_chain)
    }
}

pub(crate) fn chain_auth(data_chain: &[ChainAuth]) -> busbar_kernel::guest::LineAuth {
    let points = data_chain.iter().fold(0, |set, (_, p)| set | p.bits());
    let tail = busbar_kernel::guest::LineAuth::Chain(
        data_chain.iter().map(|(name, _)| name.clone()).collect(),
        busbar_contract::abi::auth::AuthPoints(points),
    );
    tail
}

pub(crate) fn guest_refusal(listener: &str, refusal: busbar_kernel::guest::GuestRefusal) -> String {
    use busbar_kernel::guest::{GuestRefusal, Line};
    let methods = |line: &Line| {
        [
            "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE",
        ]
        .into_iter()
        .filter(|method| {
            line.route.methods & busbar_contract::abi::transport::route::method_bit(method) != 0
        })
        .collect::<Vec<_>>()
        .join("|")
    };
    let named = |lines: &[Line]| {
        lines
            .iter()
            .map(|l| format!("{:?} {}", l.claimant, l.route.path))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let tail = match refusal {
        GuestRefusal::EqualPrecedence(pair) => format!(
            "{listener}: route conflict between {:?} {} {} and {:?} {} {}; both match at equal precedence. \
             Assign one plane to a different socket using its ingress.listen configuration, or disable one conflicting plugin",
            pair.0.claimant, methods(&pair.0), pair.0.route.path,
            pair.1.claimant, methods(&pair.1), pair.1.route.path
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
    };
    tail
}

pub(crate) const CORE_CLAIMANT: &str = "core";

#[must_use]
pub(crate) fn upgrade_carriers(
    transports: &[crate::root::linked::LinkedTransport],
    dropped: &[crate::root::registry::DroppedDoor],
) -> Vec<&'static str> {
    transport_rows(transports, dropped)
        .into_iter()
        .flat_map(|r| r.upgrades)
        .collect()
}

pub(crate) type TransportOffer = (&'static str, busbar_contract::abi::auth::AuthPoints);

/// One store and the (id, version, expiry) tickets observed through it in a batch.
type StoreTickets = (
    Arc<busbar_kernel::persistence::facade::CoreStore>,
    Vec<(Arc<str>, u64, u64)>,
);

pub(crate) struct TransportRow {
    pub(crate) upgrades: Vec<&'static str>,
}

pub(crate) fn transport_rows(
    transports: &[crate::root::linked::LinkedTransport],
    dropped: &[crate::root::registry::DroppedDoor],
) -> Vec<TransportRow> {
    let linked = transports.iter().map(|t| TransportRow {
        upgrades: (t.upgrades)(),
    });
    let dropped = dropped.iter().map(|d| TransportRow {
        upgrades: d.upgrades.clone(),
    });
    linked.chain(dropped).collect()
}

pub(crate) fn offered_by(
    offers: &[TransportOffer],
    claim: &str,
) -> busbar_contract::abi::auth::AuthPoints {
    offers
        .iter()
        .find(|(c, _)| *c == claim)
        .map_or_else(crate::root::doors::offers_unstated, |(_, o)| *o)
}

pub(crate) const SUBTREE: &str = "rest";

pub(crate) const METHODS: [RouteMethod; 5] = [
    RouteMethod::Get,
    RouteMethod::Post,
    RouteMethod::Put,
    RouteMethod::Patch,
    RouteMethod::Delete,
];

pub(crate) fn claim_line(
    instance: &str,
    rung: u32,
    claim: &crate::root::loader::dispatch::kinds::plane::OwnedClaim,
    data_chain: &[ChainAuth],
    upgrades: &[&str],
    offers: &[TransportOffer],
) -> Result<(busbar_kernel::guest::Line, Option<RouteMethod>), String> {
    use busbar_contract::abi::transport::route::{
        method_bit, METHOD_ANY, PATH_EXACT, PATH_PATTERN,
    };
    let (methods, method) = if claim.verb == "*" {
        // This is an explicit wildcard declaration, not an unknown verb's fallback. The
        // neutral guest list serves it; there is no single HTTP adapter method to mount.
        (METHOD_ANY, None)
    } else {
        let method = METHODS
            .into_iter()
            .find(|m| m.as_str() == claim.verb)
            .ok_or_else(|| {
                format!(
                    "{instance}: claim {} {} names a verb the data listener does not serve",
                    claim.verb, claim.target
                )
            })?;
        (method_bit(&claim.verb), Some(method))
    };
    let exact = claim.flags & CLAIM_EXACT != 0;
    let pattern = claim.flags & CLAIM_PATTERN != 0;
    let line = busbar_kernel::guest::Line {
        route: busbar_kernel::guest::Route {
            methods,

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

pub(crate) fn line_path(
    claim: &crate::root::loader::dispatch::kinds::plane::OwnedClaim,
    as_written: bool,
) -> String {
    if as_written {
        claim.target.clone()
    } else {
        let tail = format!("{}/{{*{SUBTREE}}}", claim.target.trim_end_matches('/'));
        tail
    }
}

pub(crate) fn signed_paths(
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

pub(crate) fn mount_paths(path: &str) -> Option<Vec<String>> {
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
    let tail = Some(vec![target, format!("{prefix}/{{*{SUBTREE}}}")]);
    tail
}

#[cfg(test)]
pub(crate) fn door_routes(
    served: Served,
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
    data_chain: &[ChainAuth],
    core: &[(String, RouteMethod, RouteAuth)],
) -> Result<Vec<PlaneRouteSpec>, String> {
    door_mounts(served, pin, data_chain, core, &[], &[]).map(|m| m.routes)
}

pub(crate) struct DoorMounts {
    /// The governed dispatcher retained with the same sealed listener generation.
    pub(crate) data: Arc<DataRoutes>,
    pub(crate) routes: Vec<PlaneRouteSpec>,

    pub(crate) sessions: Vec<busbar_kernel::plane_routes::PlaneSessionSpec>,

    pub(crate) refusals: Vec<PlaneRefusalSpec>,

    pub(crate) refuse_by_path: Option<busbar_kernel::plane_routes::PlaneRefuseByPathFn>,
}

impl std::fmt::Debug for DoorMounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorMounts")
            .field("routes", &self.routes.len())
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

#[cfg(test)]
pub(crate) fn door_mounts(
    served: Served,
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
    data_chain: &[ChainAuth],
    core: &[(String, RouteMethod, RouteAuth)],
    upgrades: &[&str],
    offers: &[TransportOffer],
) -> Result<DoorMounts, String> {
    door_mounts_planned(served, pin, data_chain, core, upgrades, offers)
}

pub(crate) fn door_mounts_planned(
    served: Served,
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
    data_chain: &[ChainAuth],
    core: &[(String, RouteMethod, RouteAuth)],
    upgrades: &[&str],
    offers: &[TransportOffer],
) -> Result<DoorMounts, String> {
    use busbar_contract::abi::transport::route::{PATH_EXACT, PATH_PATTERN};
    use busbar_kernel::guest::{Claimant, GuestList, LineAuth, Matched};
    use foldhash::HashMap;

    let mut public = public_routes(&served);
    let mut upgraded: foldhash::HashSet<DoorClaim> = foldhash::HashSet::default();
    let mut lines = Vec::new();
    let mut doors: Vec<(busbar_kernel::guest::Line, Option<RouteMethod>, DoorClaim)> = Vec::new();
    for (p, plane) in served.planes.iter().enumerate() {
        for (i, claim) in plane.snapshot.claims.iter().enumerate() {
            if !routed(claim) || lines::carrier() == Some(claim.carrier.as_str()) {
                continue;
            }
            let rung =
                u32::try_from(i).map_err(|_| format!("{}: too many claims", plane.instance))?;
            let (line, method) =
                claim_line(&plane.instance, rung, claim, data_chain, upgrades, offers)?;
            if line.upgrade.is_some() {
                upgraded.insert((p, rung));
            }
            lines.push(line.clone());
            doors.push((line, method, (p, rung)));
        }
    }

    // The native port lines join the same sealed guest list.
    lines.extend(crate::root::port_mount::guest_lines(
        &served.ports,
        data_chain,
    ));
    for (rung, (path, method, auth)) in (0u32..).zip(core) {
        lines.push(busbar_kernel::guest::Line {
            route: busbar_kernel::guest::Route {
                methods: listener_method_bits(*method),
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
                RouteAuth::None | RouteAuth::Admin => LineAuth::None,
                RouteAuth::Key => chain_auth(data_chain),
            },
            upgrade: None,

            offered: crate::root::doors::offers_unstated(),
        });
    }
    let guests =
        GuestList::seal(lines).map_err(|refusal| guest_refusal("the data listener", refusal))?;
    let post = served.post.clone().unwrap_or_else(|| {
        Arc::new(crate::root::plane_node::NodeEndPost::new(
            crate::root::plane_node::node(),
        ))
    });
    let instances: Vec<String> = served.planes.iter().map(|p| p.instance.clone()).collect();
    let documents = resource_documents(&served);

    let mut mounts: Vec<(String, RouteMethod, RouteAuth, DoorClaim)> = Vec::new();
    let mut of_line: HashMap<(String, u32), (RouteAuth, DoorClaim)> = HashMap::default();
    for (line, method, door) in doors {
        let auth = match line.auth {
            LineAuth::None => RouteAuth::None,
            LineAuth::Chain(..) => RouteAuth::Key,
        };
        of_line.insert((instances[door.0].clone(), line.route.rung), (auth, door));
        let Some(method) = method else {
            continue;
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
            if line.route.methods == busbar_contract::abi::transport::route::METHOD_ANY {
                continue;
            }
            if let Some((auth, door)) = of_line.get(&(instance.clone(), line.route.rung)) {
                mounts.push((path.clone(), method, *auth, *door));
            }
        }
    }
    let routes = DataRoutes::new(DispatchSnapshot {
        live: served
            .planes
            .iter()
            .map(|plane| plane.live.current())
            .collect(),
        entries: arrival_entries(&served),
        served,
        claim_doors: None,
        post,
        pin,
        guests,
        of_line: of_line
            .into_iter()
            .map(|(line, (_, door))| (line, door))
            .collect(),
        frames: Mutex::default(),
    })?;
    public.extend(crate::root::port_mount::routes(
        &routes.served.ports,
        routes
            .served
            .native
            .as_deref()
            .map(crate::root::min3_boot::signed_ingress),
        routes.served.billing.as_ref(),
        Some(Arc::clone(&routes)),
    ));
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
    let mut refusals: Vec<PlaneRefusalSpec> = requests
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

    refusals.extend(crate::root::port_mount::refusal_specs(&routes.served.ports));

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
            if let Some(seat) = routes
                .served
                .ports
                .iter()
                .find(|seat| &seat.instance == instance)
            {
                if !seat
                    .driver
                    .routes()
                    .data
                    .iter()
                    .any(|route| route.route == line.route.rung)
                {
                    return None;
                }
                // The kernel lends its words for this call only; the refusal keeps its own copy.
                let refusal =
                    crate::root::native_refusals::client(r.reason, r.status, r.text.to_owned());
                return Some(crate::root::port_mount::render_kernel_refusal(
                    seat,
                    line.route.rung,
                    "",
                    r.target,
                    refusal,
                ));
            }
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
            let entry = Arc::clone(&routes.entries[plane]);
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

    crate::root::inbound::stage(routes.guests.clone(), refusals.clone());
    Ok(DoorMounts {
        data: routes,
        routes: routes_of,
        sessions,
        refusals,
        refuse_by_path: Some(refuse_by_path),
    })
}

pub(crate) fn public_routes(served: &Served) -> Vec<PlaneRouteSpec> {
    let tables = &served.tables;
    let tail: Vec<PlaneRouteSpec> = served
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
        .collect();
    tail
}

pub(crate) struct ResourceDocument {
    pub(crate) resource: String,
    pub(crate) authorization_servers: Vec<String>,
    pub(crate) scopes_supported: Vec<String>,
}

pub(crate) fn resource_documents(
    served: &Served,
) -> foldhash::HashMap<(usize, u32), Arc<ResourceDocument>> {
    let mut out = foldhash::HashMap::default();
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

impl TicketCustody {
    /// Release custody of tickets the store no longer holds live (WASTE-CORE-LIFECYCLE W4). Each
    /// tick reads only the tickets within `TICKET_SKEW_SECS` of their expiry by the local clock;
    /// every `TICKET_BACKSTOP` a round-robin batch is read as well, which is how a ticket spent or
    /// deleted by another node leaves custody. Reads are batched per store. The store's clock alone
    /// decides expiry, and an unavailable or malformed observation releases nothing.
    pub(crate) async fn sweep(&self) {
        let snapshots = {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let horizon = busbar_kernel::store::now().saturating_add(TICKET_SKEW_SECS);
            let mut chosen: Vec<_> = entries
                .due
                .iter()
                .take_while(|(expires_at, _)| *expires_at <= horizon)
                .take(TICKET_SWEEP_BATCH)
                .filter_map(|(_, id)| {
                    entries.tickets.get(id).map(|e| {
                        (
                            Arc::clone(id),
                            e.version,
                            e.expires_at,
                            Arc::clone(&e.store),
                        )
                    })
                })
                .collect();
            let now = std::time::Instant::now();
            let backstop = entries
                .backstop_at
                .is_none_or(|at| now.saturating_duration_since(at) >= TICKET_BACKSTOP);
            if backstop {
                entries.backstop_at = Some(now);
                use std::ops::Bound::{Excluded, Unbounded};
                let cursor = entries.cursor.clone();
                let after = cursor.as_ref().map_or(Unbounded, |id| Excluded(&**id));
                let mut cycle: Vec<_> = entries
                    .tickets
                    .range::<str, _>((after, Unbounded))
                    .take(TICKET_SWEEP_BATCH)
                    .map(|(id, e)| {
                        (
                            Arc::clone(id),
                            e.version,
                            e.expires_at,
                            Arc::clone(&e.store),
                        )
                    })
                    .collect();
                if let Some(cursor) = cursor.as_ref() {
                    let remaining = TICKET_SWEEP_BATCH - cycle.len();
                    cycle.extend(
                        entries
                            .tickets
                            .range::<str, _>((Unbounded, std::ops::Bound::Included(&**cursor)))
                            .take(remaining)
                            .map(|(id, e)| {
                                (
                                    Arc::clone(id),
                                    e.version,
                                    e.expires_at,
                                    Arc::clone(&e.store),
                                )
                            }),
                    );
                }
                entries.cursor = cycle.last().map(|(id, ..)| Arc::clone(id));
                for ticket in cycle {
                    if !chosen.iter().any(|(id, ..)| *id == ticket.0) {
                        chosen.push(ticket);
                    }
                }
            }
            chosen
        };
        if snapshots.is_empty() {
            return;
        }
        // One batched observation per store.
        let mut by_store: Vec<StoreTickets> = Vec::new();
        for (id, version, expiry, store) in snapshots {
            match by_store
                .iter_mut()
                .find(|(held, _)| Arc::ptr_eq(held, &store))
            {
                Some((_, tickets)) => tickets.push((id, version, expiry)),
                None => by_store.push((store, vec![(id, version, expiry)])),
            }
        }
        let mut dead = Vec::new();
        for (store, tickets) in by_store {
            let items: Vec<_> = tickets
                .iter()
                .map(|(id, _, expiry)| (String::from(&**id), *expiry))
                .collect();
            #[cfg(test)]
            self.sweep_reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            match busbar_kernel::governance::ticket_records_live(store, &items).await {
                Ok(verdicts) if verdicts.len() == tickets.len() => {
                    for ((id, version, _), verdict) in tickets.into_iter().zip(verdicts) {
                        // A malformed ticket retains only itself.
                        if matches!(verdict, Ok(false)) {
                            dead.push((id, version));
                        }
                    }
                }
                Ok(_) => tracing::warn!(
                    audit = "ticket_custody_sweep_retained",
                    "ticket custody observation answered the wrong count; custody retained"
                ),
                Err(error) => tracing::warn!(
                    audit = "ticket_custody_sweep_retained",
                    error = %error.0,
                    "ticket custody observation failed; custody retained"
                ),
            }
        }
        let removed = {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            dead.into_iter()
                .filter_map(|(id, version)| {
                    if entries
                        .tickets
                        .get(&id)
                        .is_some_and(|e| e.version == version)
                    {
                        entries.remove(&id)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };
        drop(removed);
    }
}

impl DoorApply {
    pub(crate) async fn apply(&self, app: &busbar_kernel::state::App) {
        if self.served_facts.section == busbar_contract::section::RESERVED_POOLS_KEY {
            return;
        }
        let now = self.current();

        let section = applied_section(
            app,
            self.facts.plane.plane_key(),
            self.served_facts.section,
            &now,
        );

        let config = app
            .config_projection
            .as_ref()
            .and_then(|p| p.downcast_ref::<crate::root::door_steps::DoorConfig>());
        let sections = match config.map(|c| &c.sections) {
            Some(Ok(sections)) => Some(sections),
            Some(Err(error)) => {
                tracing::error!(%error, "refusing invalid plane configuration projection");
                app.plane_refresh.record(
                    self.facts.plane.plane_key(),
                    self.served_facts.section,
                    now.generation,
                    Some(busbar_kernel::state::activation::RefreshFailure::InvalidProjection),
                );
                return;
            }
            None => None,
        };
        let owned = match sections
            .map(|sections| owned_sections(&self.served_facts, sections))
            .transpose()
        {
            Ok(owned) => owned.unwrap_or_default(),
            Err(error) => {
                tracing::error!(%error, "refusing invalid plane source projection");
                app.plane_refresh.record(
                    self.facts.plane.plane_key(),
                    self.served_facts.section,
                    now.generation,
                    Some(busbar_kernel::state::activation::RefreshFailure::InvalidProjection),
                );
                return;
            }
        };

        let handed = match sections {
            Some(sections) if !section.is_null() => {
                settings_of(&self.served_facts, &section, sections)
            }
            _ => section.clone(),
        };

        let scope = busbar_contract::config_time::ConfigScope::config_time();
        match self
            .refreshed(
                &section,
                &handed,
                &owned,
                now.generation + 1,
                Arc::clone(&app.secret_resolver) as Arc<dyn busbar_contract::secret::SecretResolve>,
                &scope,
            )
            .await
        {
            Ok(next) => {
                let installed_generation = next.generation;
                *self
                    .live
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(next);
                app.plane_refresh.record(
                    self.facts.plane.plane_key(),
                    self.served_facts.section,
                    installed_generation,
                    None,
                );
                if now.generation > 1 {
                    crate::root::loader::dispatch::kinds::plane::retire_door(
                        &self.plugin,
                        now.generation - 1,
                    );
                }
            }
            Err(e) => {
                app.plane_refresh.record(
                    self.facts.plane.plane_key(),
                    self.served_facts.section,
                    now.generation,
                    Some(e.classification()),
                );
                tracing::warn!(
                    plane = self.facts.plane.plane_key(),
                    config_version = app.config_version,
                    retained_generation = now.generation,
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

    pub(crate) async fn refreshed(
        &self,
        section: &busbar_contract::yaml::Value,
        handed: &busbar_contract::yaml::Value,
        owned: &[u8],
        generation: u64,
        secrets: Arc<dyn busbar_contract::secret::SecretResolve>,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<DoorLive, DoorRefreshError> {
        crate::root::door_steps::member_tls_refusal(&self.served_facts, section)?;
        let admission = self
            .driver
            .prepare_section((self.served_facts.section, section))?;
        let settings = if section.is_null() {
            Vec::new()
        } else {
            handed_settings(settings_path(&self.served_facts), handed)?
        };
        // Every step that can refuse the section without the plugin's next generation runs
        // BEFORE the plugin refreshes: a READY refresh installs the instance's next connection
        // binding, which only `bind_fetches` below completes, so a refusal after it (a member
        // secret gone, say) would leave the retained generation serving through a binding whose
        // member routes are never bound, and its calls would wait on them forever.
        let (table, catalog_entry) = routes_of(
            section,
            self.reach.as_ref().and_then(|r| r.catalog.as_ref()),
        );
        let pools = DoorPools::of(&table, self.served_facts.section)
            .map_err(|e| format!("{}: {e}", self.facts.plane.lane_prefix()))?;
        let mut facts = self.facts.clone();
        seal_secondary_scopes(
            &mut facts,
            &self.scope_kinds,
            &pools,
            catalog_entry.as_deref(),
        );
        let routes = match &self.reach {
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
                Some(crate::root::door_steps::member_routes(
                    &table,
                    &pools,
                    &self.served_facts,
                    &reach,
                    scope,
                )?)
            }
            None => None,
        };
        let observations = crate::root::off_path::serve_observations::parse(
            self.plugin
                .service_caller()
                .ok_or_else(|| "unbound plane caller".to_owned())?
                .namespace(),
            section,
            &facts,
            &pools,
        )?;
        if !observations.is_empty() && !self.observations_supported {
            return Err("usage observations require an atomic durable store"
                .to_owned()
                .into());
        }
        crate::root::loader::dispatch::kinds::plane::refresh_door_on(
            &self.plugin,
            &self.dispatcher,
            &settings,
            owned,
            generation,
        )?;
        let binding = self.plugin.connection_binding();
        let mut fetches = None;
        let egress = match (&self.reach, routes) {
            (Some(r), Some(routes)) => {
                let egress = crate::root::door_steps::compose_egress(
                    &facts,
                    &pools,
                    binding.owner(),
                    bound_conns(binding.clone(), Arc::clone(&r.conns)),
                    &routes,
                    Arc::clone(&r.journal),
                    self.clock.clone(),
                    r.stream_ceiling_secs,
                )?;

                fetches = Some(routes);
                Some(Arc::new(egress))
            }
            _ => None,
        };
        admission
            .commit_typed()
            .await
            .map_err(DoorRefreshError::Admission)?;
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
            observations,
            ticket_nonce: Arc::new(()),
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

impl DataRoutes {
    /// Resume one Store page per opened plane through the ordinary unit machinery. Recovery
    /// carries host-owned identity only: no caller credential is reconstructed or lent.
    /// The scheduler owns cadence/shutdown; each individual poll has a finite deadline.
    pub(crate) async fn recover_work(
        self: &Arc<Self>,
        app: Arc<busbar_kernel::state::App>,
        admission: &Arc<busbar_kernel::limits::process_admission::ProcessAdmission>,
    ) -> usize {
        use busbar_kernel::guest::{Claimant, Matched};
        if app.governance.is_none() {
            return 0;
        }
        let mut attempted = 0;
        for (plane, served) in self.served.planes.iter().enumerate() {
            let work = match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                served.driver.recovery_work(),
            )
            .await
            {
                Ok(Ok(work)) => work,
                Ok(Err(error)) => {
                    tracing::warn!(instance = %served.instance, error, "durable work recovery scan failed");
                    continue;
                }
                Err(_) => continue,
            };
            for work in work {
                let now = busbar_kernel::store::now();
                let Some(key) = work.restore_for_app(&app, now) else {
                    continue;
                };
                let original_expiry = key.expires_at;
                let Some(mut key) =
                    busbar_kernel::plane_driver::standing_over(app.clone())(&key, now)
                else {
                    continue;
                };
                if let Some(original) = original_expiry {
                    let until = key
                        .expires_at
                        .map_or(original, |current| current.min(original));
                    Arc::make_mut(&mut key).expires_at = Some(until);
                }
                let path = work.target().split('?').next().unwrap_or_default();
                let claim = match self.guests.matched("GET", path, &[]) {
                    Matched::Line(line) => match &line.claimant {
                        Claimant::Plane(instance) if instance == &served.instance => self
                            .of_line
                            .get(&(instance.clone(), line.route.rung))
                            .filter(|(owner, _)| *owner == plane)
                            .map(|(_, claim)| *claim),
                        _ => None,
                    },
                    _ => None,
                };
                let Some(claim) = claim else { continue };
                let arrival = Arrival {
                    claim,
                    method: b"GET".to_vec(),
                    target: work.target().as_bytes().to_vec(),
                    fields: vec![(
                        b"x-busbar-recovery-work".to_vec(),
                        work.reference().into_bytes(),
                    )],
                    body: bytes::Bytes::new(),
                    carrier: 0,
                };
                let Ok(request) = admission
                    .try_enter(busbar_kernel::limits::process_admission::AdmissionClass::Data)
                else {
                    continue;
                };
                let principal = PrincipalId::new(key.id.as_str());
                let (caller, reply) = IngressCaller::new();
                let routes = self.clone();
                let app = app.clone();
                let unit = async move {
                    routes
                        .drive(
                            plane,
                            app,
                            (principal, Some(key), None, None, None),
                            false,
                            &caller,
                            arrival,
                            None,
                            None,
                            &request,
                        )
                        .await
                };
                // Never infer settlement from HTTP status. The plugin must publish its exact
                // receipt and settle the owned work; failed polls remain durable and retryable.
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    reply.answer_nested_bound(Box::pin(unit), NEST_REPLY_MAX),
                )
                .await;
                attempted += 1;
                drop(work);
            }
        }
        attempted
    }
}
