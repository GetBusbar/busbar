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
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::plane::{ADMIN_CARRIER_END, ROUTE_LINE};
use busbar_plugin_abi::records::{tag as g, Reply, U64Rec, Writer};
use busbar_plugin_loader::instance::{InstanceSpec, OpenError, Registry};
use busbar_plugin_loader::ports::plane::{PlaneIn, PlaneOut, PlanePort};
use busbar_plugin_loader::ports::{CallCx, PortError};

use crate::channels::line_carriers::{CarrierSink, LineCarriers};
use crate::host_services::KernelServices;

/// How long the plane has to drop its per-carrier state at a carrier's end.
const CARRIER_END_GRACE: Duration = Duration::from_secs(5);

/// Why a line got no answer line.
#[derive(Debug)]
pub enum LineRefused {
    /// The plane declares no `ROUTE_LINE` route.
    NoLineRoute,
    /// The route's auth mask names more than one class; per-request classification is a later slice.
    AuthMaskNotOneClass,
    /// The plane refused, failed or faulted.
    Port(PortError),
    /// The plane answered with an item this slice does not drive yet.
    Unsupported,
    /// The line's task was cancelled.
    Cancelled,
}

/// One line's answer as the plane's sink sees it: the to-client BODY bytes are the response line; an `Emit` is
/// written to its carrier at once, which is before this line's own response line (§12.23 rule 3).
#[derive(Default)]
pub(crate) struct LineAnswer {
    body: Vec<u8>,
    unsupported: bool,
}

impl LineAnswer {
    pub(crate) fn take(&mut self, out: PlaneOut<'_>, carriers: &LineCarriers, owner: &Incarnation) {
        match out {
            // RESPOND's status is not written on a line; the head and the end carry nothing either.
            PlaneOut::Respond { .. }
            | PlaneOut::Header(..)
            | PlaneOut::Trailers
            | PlaneOut::End
            | PlaneOut::Finish => {}
            PlaneOut::Body(bytes) => self.body.extend_from_slice(bytes),
            PlaneOut::Emit { carrier, bytes } => {
                carriers.emit_from_plane(owner, carrier, bytes);
            }
            _ => self.unsupported = true,
        }
    }

    /// The response line without its terminator; empty writes nothing.
    pub(crate) fn into_line(self) -> Result<Vec<u8>, LineRefused> {
        if self.unsupported {
            Err(LineRefused::Unsupported)
        } else {
            Ok(self.body)
        }
    }
}

/// The argument of `admin(ADMIN_CARRIER_END)`: one `U64Rec(carrier)` (§12.23 rule 5).
pub(crate) fn carrier_end_arg(carrier: u64) -> Vec<u8> {
    let mut arg = Reply::new();
    arg.put_pod(g::TEXT, &U64Rec { value: carrier })
        .expect("one eight-byte record fits an empty reply");
    arg.as_bytes().to_vec()
}

#[derive(Clone)]
struct LineRoute {
    id: u32,
    auth: u32,
    path: Box<str>,
}

/// A plane instance served through its port.
pub struct PortDriver {
    port: Arc<dyn PlanePort>,
    services: Arc<KernelServices>,
    caller: Caller,
    line: Option<LineRoute>,
}

impl PortDriver {
    /// Opens the plane instance `spec` names through the registry and binds it to the kernel's services under
    /// `caller`, the instance's own binding.
    pub async fn open<N: Needs>(
        registry: &Registry<N>,
        spec: &InstanceSpec<'_>,
        services: Arc<KernelServices>,
        caller: Caller,
    ) -> Result<Self, OpenError> {
        let port = registry.open_plane(spec).await?;
        let line = port
            .routes()
            .iter()
            .find(|r| r.flags & ROUTE_LINE != 0)
            .map(|r| LineRoute {
                id: r.route,
                auth: r.auth,
                path: r.pattern.clone(),
            });
        Ok(Self {
            port,
            services,
            caller,
            line,
        })
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
    ) -> Result<Vec<u8>, LineRefused> {
        let route = self.line.clone().ok_or(LineRefused::NoLineRoute)?;
        if route.auth.count_ones() != 1 {
            return Err(LineRefused::AuthMaskNotOneClass);
        }
        let port = Arc::clone(&self.port);
        let services = Arc::clone(&self.services);
        let owner = self.caller.incarnation().clone();
        tokio::task::spawn_blocking(move || {
            run_line(
                &*port,
                services.line_carriers(),
                &owner,
                &route,
                carrier.get(),
                request_id,
                &line,
            )
        })
        .await
        .map_err(|_| LineRefused::Cancelled)?
    }
}

fn run_line(
    port: &dyn PlanePort,
    carriers: &LineCarriers,
    owner: &Incarnation,
    route: &LineRoute,
    carrier: u64,
    request_id: u64,
    line: &[u8],
) -> Result<Vec<u8>, LineRefused> {
    let req = PlaneIn {
        route: route.id,
        flags: 0,
        auth: route.auth,
        method: "POST",
        path: &route.path,
        query: "",
        headers: &[],
        identity: &[],
        request_id,
        carrier,
        work: "",
        ticket_record: &[],
    };
    let mut answer = LineAnswer::default();
    let session = port
        .request(&req, line, &mut |out: PlaneOut<'_>| {
            answer.take(out, carriers, owner);
        })
        .map_err(LineRefused::Port)?;
    // A session dropped without `end` is a cancel (§10.4); the plane answered locally here, so it ends.
    port.end(session, &mut |out: PlaneOut<'_>| {
        answer.take(out, carriers, owner);
    })
    .map_err(LineRefused::Port)?;
    answer.into_line()
}

#[cfg(test)]
#[path = "tests/port_tests.rs"]
mod tests;
