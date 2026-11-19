// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The serving generation's composition: what `serve` builds once per configuration, per published
//! generation or per process lifecycle (its native seats and their billing, the data listener's
//! mounts, its boot-time workers), never per request. The request path only reads what this built;
//! `serve` re-exports it.

use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_kernel::plane_driver::serve::ServeTables;
use busbar_kernel::plane_driver::PlaneMoney;
use busbar_kernel::plane_routes::{PlaneRefusalSpec, PlaneRouteSpec};

use crate::root::serve::*;

impl Served {
    /// One process-owned scanner. Kept and joined by main before storage retirement.
    pub(crate) fn spawn_work_recovery(
        &self,
        app: Arc<busbar_kernel::state::AppHandle>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        struct Ready(Option<Arc<crate::root::min3_boot::Booted>>);
        impl Drop for Ready {
            fn drop(&mut self) {
                if let Some(native) = &self.0 {
                    crate::root::min3_boot::set_recovery_ready(native, false);
                }
            }
        }
        // The MIN-3 plane seats' durable WORK is recovered by this scheduler (IF §12.24 step 3).
        let native = self.native.clone();
        let ready = Ready(native.clone());
        let ports = native
            .as_ref()
            .is_some_and(|booted| !booted.seats.is_empty());
        if let Some(native) = &native {
            crate::root::min3_boot::set_recovery_ready(native, ports);
        }
        tokio::spawn(async move {
            let _ready = ready;
            let Some(native) = native.filter(|_| ports) else {
                return;
            };
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.recv() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                }
                tokio::select! {
                    biased;
                    _ = shutdown.recv() => break,
                    _ = crate::root::min3_boot::recover_ports(&native, app.load()) => {}
                }
            }
        })
    }

    pub(crate) fn spawn_ticks(&self) {
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

/// THE SERVING GENERATION'S PLANES, composed once after the first app is built: the native seats
/// `min3_boot::finish` opened, the node's posting site and, with a governance book, the billing of
/// the requests those seats serve. With no book a port request is not a billed unit (audit rows
/// only).
pub(crate) fn compose_native(
    native: Arc<crate::root::min3_boot::Booted>,
    gov: Option<Arc<busbar_kernel::governance::GovState>>,
    tables: &ServeTables,
) -> Served {
    let ports = native.seats.clone();
    let Some(gov) = gov else {
        return Served {
            ports,
            native: Some(native),
            tables: tables.clone(),
            ..Served::default()
        };
    };
    let node = crate::root::plane_node::node();
    let post = Arc::new(crate::root::plane_node::NodeEndPost::new(Arc::clone(&node)));
    let billing = busbar_kernel::plane_driver::port_billing::PortBilling::new(
        Arc::new(PlaneMoney::new(
            Arc::clone(&gov),
            Arc::clone(&post) as Arc<dyn busbar_kernel::plane_driver::EndPost>,
        )),
        Arc::clone(&gov),
        node.kernel_and_keys().1,
        Arc::new(busbar_kernel::plane_driver::CoreAudit),
    )
    .with_journal(Arc::clone(&post) as Arc<dyn busbar_kernel::plane_driver::HookJournal>);
    Served {
        ports,
        native: Some(native),
        post: Some(post),
        billing: Some(billing),
        tables: tables.clone(),
        ..Served::default()
    }
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

pub(crate) const METHODS: [RouteMethod; 5] = [
    RouteMethod::Get,
    RouteMethod::Post,
    RouteMethod::Put,
    RouteMethod::Patch,
    RouteMethod::Delete,
];

/// The data listener's mounts for one serving generation: the sealed guest list and dispatch
/// snapshot, the native seats' routes and refusals, and the kernel refusal renderer.
pub(crate) struct DataMounts {
    /// The dispatch snapshot retained with the same sealed listener generation.
    pub(crate) data: Arc<DataRoutes>,
    pub(crate) routes: Vec<PlaneRouteSpec>,

    pub(crate) refusals: Vec<PlaneRefusalSpec>,

    pub(crate) refuse_by_path: Option<busbar_kernel::plane_routes::PlaneRefuseByPathFn>,
}

impl std::fmt::Debug for DataMounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataMounts")
            .field("routes", &self.routes.len())
            .finish()
    }
}

/// Seal the data listener's guest list (the native port lines and core's own lines) and build the
/// generation's mounts over it.
pub(crate) fn data_mounts(
    served: Served,
    data_chain: &[ChainAuth],
    core: &[(String, RouteMethod, RouteAuth)],
) -> Result<DataMounts, String> {
    use busbar_contract::abi::transport::route::{PATH_EXACT, PATH_PATTERN};
    use busbar_kernel::guest::{Claimant, GuestList, LineAuth, Matched};

    let mut lines = crate::root::port_mount::guest_lines(&served.ports, data_chain);
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

            offered: crate::root::port_mount::LINE_OFFERED,
        });
    }
    let guests =
        GuestList::seal(lines).map_err(|refusal| guest_refusal("the data listener", refusal))?;
    let post = served.post.clone().unwrap_or_else(|| {
        Arc::new(crate::root::plane_node::NodeEndPost::new(
            crate::root::plane_node::node(),
        ))
    });
    let routes = DataRoutes::new(DispatchSnapshot {
        served,
        post,
        guests,
        frames: Mutex::default(),
    })?;
    let mounted = crate::root::port_mount::routes(
        &routes.served.ports,
        routes
            .served
            .native
            .as_deref()
            .map(crate::root::min3_boot::signed_ingress),
        routes.served.billing.as_ref(),
        Some(Arc::clone(&routes)),
    );
    let refusals = crate::root::port_mount::refusal_specs(&routes.served.ports);

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
            let seat = routes
                .served
                .ports
                .iter()
                .find(|seat| &seat.instance == instance)?;
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
            let refusal = crate::root::native_refusals::client(r.reason, r.status, r.text.to_owned());
            Some(crate::root::port_mount::render_kernel_refusal(
                seat,
                line.route.rung,
                "",
                r.target,
                refusal,
            ))
        })
    };
    Ok(DataMounts {
        data: routes,
        routes: mounted,
        refusals,
        refuse_by_path: Some(refuse_by_path),
    })
}
