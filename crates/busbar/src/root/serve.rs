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
use busbar_contract::caps::OpClassId;
use busbar_contract::caps::ReasonCode;
use busbar_contract::plane::{declares_record_kind, PlaneDeclaration};
use busbar_contract::plane_calls::PlaneCalls;
use busbar_contract::services::{Caller, HostServices, Later, Ran, Reading, RecordsList, Stored};
use busbar_kernel::host_records::QUEUE_CAP;
use busbar_kernel::host_services::{BlockingPool, DestJudge, KernelServices, SignKey};
use busbar_kernel::plane::store::KIND_DEMOTION;
use busbar_kernel::plane::DemotionRecord;
use busbar_kernel::plane_driver::serve::{publish, ServeRoute, ServeTable};
use busbar_kernel::plane_driver::{
    refusal_status, BufferCaps, CallerEnd, DriverConfig, HeadFields, MoneySeam, PlaneDriver,
};
use tokio::sync::{mpsc, oneshot};

use crate::root::boot::DoorPlane;
use crate::root::loader::dispatch::kinds::plane::OwnedSnapshot;
use crate::root::loader::dispatch::plane_calls::PlaneInstance;
use crate::root::loader::dispatch::{in_head, out_head, Dispatcher, Frame};

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
/// [`LateServices`], before any plugin is bound; the kernel's own services are kept whole for the
/// late attach and the plane driver ([`LateServices::kernel`]). A second call (a reload) installs
/// nothing.
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
    if late.install_composed(kernel, Arc::new(services)).is_err() {
        tracing::debug!("the kernel's host services were already installed");
    }
}

/// THE LATE ATTACH, once the first app is built (ARCHITECT S7-TICK 2026-10-01, ruling A): the
/// kernel's services gain what that build made. That is the runtime's blocking pool, bounded at the
/// record write queue's [`QUEUE_CAP`]; the governance signer, when governance is configured; and
/// the durable demotion record, its unprefixed rows belonging to the one plane that declares the
/// demotion record kind ([`demotion_owner`]). Each lives for the process (an apply reuses the
/// governance state and carries the demotion record), so each attaches once. With no kernel
/// services composed it attaches nothing. Runs on the runtime.
pub fn attach(
    late: &LateServices,
    signer: Option<Arc<dyn SignKey>>,
    demotions: &Arc<DemotionRecord>,
    planes: &[&PlaneDeclaration],
) {
    let Some(kernel) = late.kernel() else {
        return;
    };
    let pool = BlockingPool::new(tokio::runtime::Handle::current(), QUEUE_CAP);
    kernel.attach_pool(Arc::new(pool));
    if let Some(signer) = signer {
        kernel.attach_signer(signer);
    }
    if let Some(owner) = demotion_owner(planes) {
        kernel.attach_demotions(Arc::clone(demotions), owner);
    }
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

    /// Install the kernel's own services, as [`Self::install`] does, and keep them whole for the
    /// late attach ([`attach`]) and the plane driver ([`Self::kernel`]).
    pub fn install_kernel(&self, services: Arc<KernelServices>) -> Result<(), AlreadyInstalled> {
        self.install_composed(Arc::clone(&services), services)
    }

    /// Install `served` (the kernel's services as the root composes them over `kernel`: the
    /// credential read layered on, [`compose`]), as [`Self::install`] does, and keep `kernel` whole
    /// for the late attach ([`attach`]) and the plane driver ([`Self::kernel`]).
    pub fn install_composed(
        &self,
        kernel: Arc<KernelServices>,
        served: Arc<dyn HostServices>,
    ) -> Result<(), AlreadyInstalled> {
        self.install(served)?;
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
    fn dest_judge(&self, dest: &str, class: u32, resolve: bool, later: Option<Later>) -> Ran {
        match self.served() {
            Ok(s) => s.dest_judge(dest, class, resolve, later),
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
}

// ── the door planes, composed ─────────────────────────────────────────────────────────────────────

/// ONE DOOR PLANE, COMPOSED (TODO U6-U7, ARCHITECT Q-SW4 2026-10-02): its instance, the driver the
/// kernel serves it through, and the snapshot its `open` published (its claims and admin routes).
pub struct ServedPlane {
    /// The instance's label.
    pub instance: String,
    /// The plane's driver: admitted to the kernel's services, its driver ticket minted.
    pub driver: Arc<PlaneDriver>,
    /// The first generation's snapshot, as the host copied it.
    pub snapshot: OwnedSnapshot,
}

impl std::fmt::Debug for ServedPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServedPlane")
            .field("instance", &self.instance)
            .field("snapshot", &self.snapshot)
            .finish_non_exhaustive()
    }
}

/// EVERY DOOR PLANE THIS PROCESS SERVES, composed once after the first app is built.
#[derive(Debug, Default)]
pub struct Served {
    /// In the order the planes were bound.
    pub planes: Vec<ServedPlane>,
}

impl Served {
    /// Each plane's tick schedule, on its driver ticket, spawned on the current runtime.
    pub fn spawn_ticks(&self) {
        for p in &self.planes {
            let driver = Arc::clone(&p.driver);
            tokio::spawn(async move { driver.ticks().await });
        }
    }
}

/// THE DOOR PLANES' COMPOSITION (ARCHITECT Q-SW4, 2026-10-02): every plane bound through its door
/// (`root::boot::door_planes`) whose declared section this deployment writes (LAW 7: a plugin
/// loads iff its section is present) is opened with that section as its settings, and composed:
/// a [`PlaneInstance`] on `dispatcher` (unit tickets on worker 0, where its driver ticket is
/// minted), a [`PlaneDriver`] admitted to the kernel's composed services with the plane's tail
/// facts and a money seam from `money`, and its admin routes published on the admin router's table
/// (`plane_driver::serve`, K-SERVE). A plane whose section is absent stays bound and unopened, as
/// before. Nothing here mounts a data route: a claimed arrival reaches a driver only once the
/// plane's door row is served (P2).
///
/// # Errors
///
/// A plane that will not open, publish a snapshot, be admitted or publish its admin routes, named:
/// the boot refuses it, as it refuses a plane that will not bind.
pub fn compose_planes(
    doors: &[(String, DoorPlane)],
    dispatcher: &Arc<Dispatcher>,
    late: &LateServices,
    sections: &BTreeMap<&'static str, serde_yaml::Value>,
    money: &dyn Fn() -> Arc<dyn MoneySeam>,
) -> Result<Served, String> {
    let mut served = Served::default();
    if doors.is_empty() {
        return Ok(served);
    }
    let kernel = late
        .kernel()
        .ok_or("the kernel's host services are not composed")?;
    for (instance, plugin) in doors {
        let facts = plugin.served();
        let Some(section) = sections.get(facts.section) else {
            tracing::debug!(
                instance,
                section = facts.section,
                "door plane not configured"
            );
            continue;
        };
        let snapshot = open(plugin, section).map_err(|e| format!("{instance}: {e}"))?;
        let calls = Arc::new(PlaneInstance::new(
            plugin.clone(),
            Arc::clone(dispatcher),
            0,
        ));
        let config = DriverConfig {
            caps: BufferCaps::default(),
            op_classes: facts.op_classes.iter().map(|c| OpClassId::new(c)).collect(),
            status_of: refusal_status,
            refusal_statuses: calls.refusal_statuses(),
            caller_refs: None,
        };
        let caller = Caller {
            instance: Arc::from(instance.as_str()),
            plugin: Arc::from(plugin.name()),
            kind: KindCode::Plane,
        };
        let driver = PlaneDriver::new(
            Arc::clone(&calls) as Arc<dyn PlaneCalls>,
            config,
            money(),
            Arc::clone(&kernel),
            (facts.section, section),
        )
        .map_err(|e| format!("{instance}: {e}"))?
        .with_records(Arc::clone(&kernel), caller);
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
        // The admin router's fallback is this table, so a kernel admin route always matches first
        // and is never shadowed; no route is reserved beyond that.
        publish(
            ServeTable {
                instance: instance.clone(),
                audit_kind: facts.audit_kind.to_string(),
                calls,
                caps: BufferCaps::default(),
                routes,
            },
            &[],
        )
        .map_err(|c| format!("{instance}: admin route {:?} overlaps {}", c.route, c.with))?;
        served.planes.push(ServedPlane {
            instance: instance.clone(),
            driver: Arc::new(driver),
            snapshot,
        });
    }
    Ok(served)
}

/// `open` the plane, generation 1, its settings `section` as JSON; the snapshot it published.
fn open(plugin: &DoorPlane, section: &serde_yaml::Value) -> Result<OwnedSnapshot, String> {
    let settings = serde_json::to_vec(section).map_err(|e| format!("its section: {e}"))?;
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
                ptr: std::ptr::null(),
                len: 0,
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

// ── the driver's caller side over today's ingress ────────────────────────────────────────────────

/// THE CALLER'S SIDE OF A DRIVEN UNIT over today's hyper ingress (TRANSITIONAL: deleted when
/// INBOUND-LISTEN's `accepted::Caller` serves the data door, 1.6.0-TODO "TRANSITIONAL ROWS").
///
/// The head goes to the handler once; the bytes go into the response body through a channel of one
/// piece, so a `write` resolves only once the body has taken the piece before it (the caller's side
/// was writable). A body the server dropped (the caller went away) answers `false`.
#[derive(Debug)]
pub struct IngressCaller {
    head: Mutex<Option<oneshot::Sender<Head>>>,
    body: mpsc::Sender<Bytes>,
}

/// A reply head: the status number and the head fields.
type Head = (u32, HeadFields);

/// The handler's end of an [`IngressCaller`]: the reply, once the unit states its head.
#[derive(Debug)]
pub struct IngressReply {
    head: oneshot::Receiver<Head>,
    body: mpsc::Receiver<Bytes>,
}

impl IngressCaller {
    /// A caller side and the reply it feeds.
    #[must_use]
    pub fn new() -> (Self, IngressReply) {
        let (head_tx, head) = oneshot::channel();
        let (body_tx, body) = mpsc::channel(1);
        let caller = IngressCaller {
            head: Mutex::new(Some(head_tx)),
            body: body_tx,
        };
        (caller, IngressReply { head, body })
    }
}

impl CallerEnd for IngressCaller {
    fn head(&self, status: u32, fields: HeadFields) {
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

impl IngressReply {
    /// The response, once the unit has stated its head; `None` when the unit ended without one.
    /// A status the wire cannot carry is the plane's fault, answered as the driver answers a
    /// plane fault; a field the wire cannot carry is not sent.
    pub async fn response(self) -> Option<Response> {
        let (status, fields) = self.head.await.ok()?;
        // The driver's own status for a plane fault, when the plane's cannot go on the wire.
        let status = [status, refusal_status(ReasonCode::PlanePanic)]
            .into_iter()
            .find_map(|s| StatusCode::from_u16(u16::try_from(s).ok()?).ok())?;
        let mut response = Response::new(Body::new(ReplyBody(self.body)));
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
        Some(response)
    }
}

/// The response body: the pieces the unit writes, in order, until its caller side is dropped.
struct ReplyBody(mpsc::Receiver<Bytes>);

impl http_body::Body for ReplyBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.0
            .poll_recv(cx)
            .map(|piece| piece.map(|bytes| Ok(http_body::Frame::data(bytes))))
    }
}

#[cfg(test)]
#[path = "tests/serve.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/serve_planes.rs"]
mod planes_tests;
