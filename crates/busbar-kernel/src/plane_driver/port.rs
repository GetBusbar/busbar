// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane driver over the MIN-3 plane port (IF §11.3, §12.23). A [`PortDriver`] owns one plane instance opened
//! by `Registry::open_plane` and serves it through `PlanePort` alone: no `PlaneCalls`, no old `abi::plane`. It grows
//! slice by slice (PLANE-DRIVER.md) until it replaces `PlaneDriver`; this slice drives the stdin/stdout line carrier
//! (`ROUTE_LINE`): `request`, `end`, `PlaneOut::Emit` into `LineCarriers::emit_from_plane`, and
//! `admin(ADMIN_CARRIER_END)` once per carrier.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::services::{Caller, Incarnation};
use busbar_plugin_abi::fail::failed::F_INTERNAL;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::plane::{ADMIN_CARRIER_END, ADMIN_TICK, ROUTE_LINE};
use busbar_plugin_abi::records::{tag as g, Reply, U64Rec, Writer};
use busbar_plugin_loader::instance::{InstanceSpec, OpenError, Registry};
use busbar_plugin_loader::ports::plane::{PlaneIn, PlanePort};
use busbar_plugin_loader::ports::{CallCx, PortError};

use crate::channels::line_carriers::{CarrierSink, LineCarriers};
use crate::host_services::KernelServices;

use super::port_auth::{
    admit, effective_classes, refuse, subject_identity, Admitted, Credentials, NoTickets, Principal,
};
use super::port_channels::{decode_tick, TickOut};
use super::port_money::write_audit;
use super::port_session::{run_local, Effects, SessionError, ToClient};
use super::{AuditSink, CoreAudit};
use crate::refusal::{ClientRefusal, RefusalMap};

/// How long the plane has to drop its per-carrier state at a carrier's end.
const CARRIER_END_GRACE: Duration = Duration::from_secs(5);

/// How long the plane has to answer one tick.
const TICK_GRACE: Duration = Duration::from_secs(30);

/// Why a line got no answer line.
#[derive(Debug)]
pub enum LineRefused {
    /// The plane declares no `ROUTE_LINE` route.
    NoLineRoute,
    /// The plane refused, failed or faulted, or broke a once rule, or answered with an item a later slice drives.
    Session(SessionError),
    /// The line's task was cancelled.
    Cancelled,
}

/// A line's effects outside its response line: an `Emit` is written to its carrier at once, which is before this
/// line's own response line (§12.23 rule 3).
struct LineEffects<'a> {
    carriers: &'a LineCarriers,
    owner: &'a Incarnation,
}

impl Effects for LineEffects<'_> {
    fn emit(&self, carrier: u64, bytes: &[u8]) {
        self.carriers.emit_from_plane(self.owner, carrier, bytes);
    }
}

/// The response line without its terminator: the to-client BODY bytes. RESPOND's status, the head and the end
/// carry nothing on a line; empty writes nothing. A message item has no line form.
fn line_of(items: Vec<ToClient>) -> Result<Vec<u8>, LineRefused> {
    let mut line = Vec::new();
    for item in items {
        match item {
            ToClient::Body(bytes) => line.extend_from_slice(&bytes),
            ToClient::Msg { .. } => return Err(LineRefused::Session(SessionError::NotDriven)),
            ToClient::Head { .. } | ToClient::Trailers(_) | ToClient::End => {}
        }
    }
    Ok(line)
}

/// The argument of `admin(ADMIN_CARRIER_END)`: one `U64Rec(carrier)` (§12.23 rule 5).
pub(crate) fn carrier_end_arg(carrier: u64) -> Vec<u8> {
    let mut arg = Reply::new();
    arg.put_pod(g::TEXT, &U64Rec { value: carrier })
        .expect("one eight-byte record fits an empty reply");
    arg.as_bytes().to_vec()
}

/// One served MIN-3 plane instance: its driver and the audience its line session is bound to (the `canonical_uri`
/// of its config block, `None` when it states none).
#[derive(Clone)]
pub struct PortSeat {
    pub instance: String,
    pub driver: Arc<PortDriver>,
    pub audience: Option<String>,
}

impl std::fmt::Debug for PortSeat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortSeat")
            .field("instance", &self.instance)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct LineRoute {
    id: u32,
    /// The effective class set (IF §12.11) the route runs under; a line classifies each request within it.
    effective: u32,
    path: Box<str>,
}

/// A plane instance served through its port.
pub struct PortDriver {
    port: Arc<dyn PlanePort>,
    services: Arc<KernelServices>,
    caller: Caller,
    refusals: Arc<dyn RefusalMap>,
    audit: Arc<dyn AuditSink>,
    line: Option<LineRoute>,
}

impl PortDriver {
    /// Opens the plane instance `spec` names through the registry and binds it to the kernel's services under
    /// `caller`, the instance's own binding. `refusals` is the map every refusal this driver renders goes through.
    pub async fn open<N: Needs>(
        registry: &Registry<N>,
        spec: &InstanceSpec<'_>,
        services: Arc<KernelServices>,
        caller: Caller,
        refusals: Arc<dyn RefusalMap>,
    ) -> Result<Self, OpenError> {
        let port = registry.open_plane(spec).await?;
        let line = port
            .routes()
            .iter()
            .find(|r| r.flags & ROUTE_LINE != 0)
            .and_then(|r| {
                Some(LineRoute {
                    id: r.route,
                    effective: effective_classes(r.auth, None).ok()?,
                    path: r.pattern.clone(),
                })
            });
        Ok(Self {
            port,
            services,
            caller,
            refusals,
            audit: Arc::new(CoreAudit),
            line,
        })
    }

    /// The audit chain this driver writes a plane's AUDIT rows to (default: the kernel's own, [`CoreAudit`]).
    #[must_use]
    pub fn with_audit(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.audit = audit;
        self
    }

    /// D_TICK_S: the period core calls [`tick`](Self::tick) at, if the plane declares one.
    #[must_use]
    pub fn tick_s(&self) -> Option<u64> {
        self.port.tick_s()
    }

    /// One `admin(ADMIN_TICK)` (§8.6): the plane's EMITs are written to their carriers at once (an ended carrier,
    /// or one another instance owns, drops it and counts), and its PUSHes are returned for the push queue, which
    /// belongs to the caller (it enqueues them under the instance's namespace, §12.9).
    ///
    /// # Errors
    /// The plane refused, failed or faulted, or its answer is not records.
    pub async fn tick(&self) -> Result<TickOut, PortError> {
        let cx = CallCx {
            deadline: Instant::now() + TICK_GRACE,
            request_id: 0,
            stack: Default::default(),
        };
        let answer = self.port.admin(cx, ADMIN_TICK, &[]).await?;
        let out = decode_tick(&answer).map_err(|_| PortError::Failed {
            code: F_INTERNAL,
            text: "the plane tick answer is not records".into(),
            retry_after_s: None,
            backend_status: None,
            error: None,
        })?;
        for (carrier, bytes) in &out.emits {
            self.services.line_carriers().emit_from_plane(
                self.caller.incarnation(),
                *carrier,
                bytes,
            );
        }
        Ok(out)
    }

    /// Whether the plane declares a `ROUTE_LINE` route.
    #[must_use]
    pub fn serves_lines(&self) -> bool {
        self.line.is_some()
    }

    /// Opens a line carrier owned by this instance, serving as `principal`, written through `sink`.
    pub fn open_carrier(&self, principal: &str, sink: CarrierSink) -> NonZeroU64 {
        NonZeroU64::new(
            self.services
                .open_carrier_session(&self.caller, principal, sink),
        )
        .expect("kernel carrier sessions are minted above zero")
    }

    /// Closes the carrier's writer side: an `Emit` to it is dropped from here on.
    pub fn close_carrier(&self, carrier: NonZeroU64) {
        self.services.close_carrier_session(carrier.get());
    }

    /// Tells the plane the carrier has ended, once, after its line sessions ended and its writer closed. The plane
    /// answers nothing; a plane that fails here has its fault handled by the port, and the carrier is gone anyway.
    pub async fn carrier_ended(&self, carrier: NonZeroU64) {
        let arg = carrier_end_arg(carrier.get());
        let cx = CallCx {
            deadline: Instant::now() + CARRIER_END_GRACE,
            request_id: 0,
            stack: Default::default(),
        };
        if let Err(error) = self.port.admin(cx, ADMIN_CARRIER_END, &arg).await {
            tracing::warn!(?error, carrier = carrier.get(), "plane carrier end failed");
        }
    }

    /// Serves one line of `carrier`: `request`, then `end`. The response line, without its terminator, is empty
    /// when the plane wrote no body. The plane's calls are synchronous, so they run off the executor.
    pub async fn answer_line(
        &self,
        carrier: NonZeroU64,
        request_id: u64,
        line: Vec<u8>,
        from: &LineCaller,
    ) -> Result<Vec<u8>, LineRefused> {
        let route = self.line.clone().ok_or(LineRefused::NoLineRoute)?;
        let admission = admit_line(route.id, route.effective, from, &*self.refusals).await;
        let refusals = Arc::clone(&self.refusals);
        let audit = Arc::clone(&self.audit);
        let principal = Arc::clone(&from.principal);
        let port = Arc::clone(&self.port);
        let services = Arc::clone(&self.services);
        let owner = self.caller.incarnation().clone();
        tokio::task::spawn_blocking(move || {
            run_line(
                &*port,
                &*refusals,
                &*audit,
                &principal,
                services.line_carriers(),
                &owner,
                &route,
                admission,
                carrier.get(),
                request_id,
                &line,
            )
        })
        .await
        .map_err(|_| LineRefused::Cancelled)?
    }
}

/// The carrier's own binding, as its lines see it: the principal its session was bound as, and whether that was a
/// verified credential (an unbound session is anonymous).
#[derive(Clone, Debug)]
pub struct LineCaller {
    pub principal: Arc<str>,
    pub authenticated: bool,
}

/// A line's admission (IF §12.11): the carrier's principal is the one credential a line has, so a PRINCIPAL route
/// takes it as the identity (ID_SUBJECT), OPTIONAL takes it when the carrier is authenticated, PUBLIC takes none.
/// A line has no credential header, so a ticket never applies and PRINCIPAL beside TICKET runs PRINCIPAL.
pub(crate) async fn admit_line(
    route: u32,
    effective: u32,
    caller: &LineCaller,
    refusals: &dyn RefusalMap,
) -> Result<Admitted, ClientRefusal> {
    let identity = subject_identity(&caller.principal);
    let principal = if caller.authenticated {
        Principal::Verified(&identity)
    } else {
        Principal::Anonymous
    };
    let creds = Credentials {
        bearer: None,
        principal,
        operator: false,
        signed: None,
    };
    admit(route, effective, &creds, &NoTickets, refusals, "", 0).await
}

/// What a port error becomes for the client: core's generic refusal, never the plugin's words (§12.15).
pub(crate) fn refusal_of(
    route: u32,
    error: &PortError,
    refusals: &dyn RefusalMap,
) -> ClientRefusal {
    refusals.for_port(route, error)
}

/// One line: admission, then `request` and `end`. A refused admission, or a `request` the plane refused or
/// failed, is rendered by the plane (`render(RENDER_REFUSAL)`) and its body is the response line.
#[allow(clippy::too_many_arguments)]
fn run_line(
    port: &dyn PlanePort,
    refusals: &dyn RefusalMap,
    audit: &dyn AuditSink,
    principal: &str,
    carriers: &LineCarriers,
    owner: &Incarnation,
    route: &LineRoute,
    admission: Result<Admitted, ClientRefusal>,
    carrier: u64,
    request_id: u64,
    line: &[u8],
) -> Result<Vec<u8>, LineRefused> {
    let effects = LineEffects { carriers, owner };
    let build = |auth: u32, identity: &'_ [u8], ticket_record: &'_ [u8]| PlaneIn {
        route: route.id,
        flags: 0,
        auth,
        method: "POST",
        path: &route.path,
        query: "",
        headers: &[],
        identity,
        request_id,
        carrier,
        work: "",
        ticket_record,
    };
    let admitted = match admission {
        Ok(admitted) => admitted,
        Err(refusal) => {
            let lowest = route.effective & route.effective.wrapping_neg();
            let req = build(lowest, &[], &[]);
            return line_of(refuse(port, &req, &refusal, &effects));
        }
    };
    let req = build(admitted.auth, &admitted.identity, admitted.ticket_record());
    // A session dropped without `end` is a cancel (§10.4); the plane answers locally on a line, so it ends.
    match run_local(port, &req, line, &effects) {
        Ok(local) => {
            for row in &local.audits {
                if write_audit(audit, row, Some(principal)).is_err() {
                    tracing::warn!(action = &*row.action, "a plane audit row was not accepted");
                }
            }
            line_of(local.client)
        }
        Err(SessionError::Port(error)) => {
            let refusal = refusal_of(route.id, &error, refusals);
            line_of(refuse(port, &req, &refusal, &effects))
        }
        Err(error) => Err(LineRefused::Session(error)),
    }
}

#[cfg(test)]
#[path = "tests/port_tests.rs"]
mod tests;
